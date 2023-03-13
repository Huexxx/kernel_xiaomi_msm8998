// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017-2018 HUAWEI, Inc.
 *             https://www.huawei.com/
 * Copyright (C) 2021, Alibaba Cloud
 */
#include "internal.h"
#include <linux/prefetch.h>

#include <trace/events/erofs.h>

static void erofs_readendio(struct bio *bio)
{
	int i;
	struct bio_vec *bvec;
	blk_status_t err = bio->bi_status;

	bio_for_each_segment_all(bvec, bio, i) {
		struct page *page = bvec->bv_page;

		/* page is already locked */
		DBG_BUGON(PageUptodate(page));

		if (err)
			SetPageError(page);
		else
			SetPageUptodate(page);

		unlock_page(page);
		/* page could be reclaimed now */
	}
	bio_put(bio);
}

struct page *erofs_get_meta_page(struct super_block *sb, erofs_blk_t blkaddr)
{
	struct address_space *const mapping = sb->s_bdev->bd_inode->i_mapping;
	struct page *page;

	page = read_cache_page_gfp(mapping, blkaddr,
				   mapping_gfp_constraint(mapping, ~__GFP_FS));
	/* should already be PageUptodate */
	if (!IS_ERR(page))
		lock_page(page);
	return page;
}

void erofs_unmap_metabuf(struct erofs_buf *buf)
{
	if (buf->kmap_type == EROFS_KMAP)
		kunmap(buf->page);
	else if (buf->kmap_type == EROFS_KMAP_ATOMIC)
		kunmap_atomic(buf->base);
	buf->base = NULL;
	buf->kmap_type = EROFS_NO_KMAP;
}

void erofs_put_metabuf(struct erofs_buf *buf)
{
	if (!buf->page)
		return;
	erofs_unmap_metabuf(buf);
	put_page(buf->page);
	buf->page = NULL;
}

/*
 * Derive the block size from inode->i_blkbits to make compatible with
 * anonymous inode in fscache mode.
 */
void *erofs_bread(struct erofs_buf *buf, struct inode *inode,
		  erofs_blk_t blkaddr, enum erofs_kmap_type type)
{
	erofs_off_t offset = (erofs_off_t)blkaddr << inode->i_blkbits;
	struct address_space *const mapping = inode->i_mapping;
	pgoff_t index = offset >> PAGE_SHIFT;
	struct page *page = buf->page;

	if (!page || page->index != index) {
		erofs_put_metabuf(buf);
		page = read_cache_page_gfp(mapping, index,
				mapping_gfp_constraint(mapping, ~__GFP_FS));
		if (IS_ERR(page))
			return page;
		/* should already be PageUptodate, no need to lock page */
		buf->page = page;
	}
	if (buf->kmap_type == EROFS_NO_KMAP) {
		if (type == EROFS_KMAP)
			buf->base = kmap(page);
		else if (type == EROFS_KMAP_ATOMIC)
			buf->base = kmap_atomic(page);
		buf->kmap_type = type;
	} else if (buf->kmap_type != type) {
		DBG_BUGON(1);
		return ERR_PTR(-EFAULT);
	}
	if (type == EROFS_NO_KMAP)
		return NULL;
	return buf->base + (offset & ~PAGE_MASK);
}

void *erofs_read_metabuf(struct erofs_buf *buf, struct super_block *sb,
			 erofs_blk_t blkaddr, enum erofs_kmap_type type)
{
	return erofs_bread(buf, sb->s_bdev->bd_inode, blkaddr, type);
}

static int erofs_map_blocks_flatmode(struct inode *inode,
				     struct erofs_map_blocks *map)
{
	erofs_blk_t nblocks, lastblk;
	u64 offset = map->m_la;
	struct erofs_inode *vi = EROFS_I(inode);
	struct super_block *sb = inode->i_sb;
	bool tailendpacking = (vi->datalayout == EROFS_INODE_FLAT_INLINE);

	nblocks = erofs_iblks(inode);
	lastblk = nblocks - tailendpacking;

	/* there is no hole in flatmode */
	map->m_flags = EROFS_MAP_MAPPED;
	if (offset < erofs_pos(sb, lastblk)) {
		map->m_pa = erofs_pos(sb, vi->raw_blkaddr) + map->m_la;
		map->m_plen = erofs_pos(sb, lastblk) - offset;
	} else if (tailendpacking) {
		map->m_pa = erofs_iloc(inode) + vi->inode_isize +
			vi->xattr_isize + erofs_blkoff(sb, offset);
		map->m_plen = inode->i_size - offset;

		/* inline data should be located in the same meta block */
		if (erofs_blkoff(sb, map->m_pa) + map->m_plen > sb->s_blocksize) {
			erofs_err(sb, "inline data cross block boundary @ nid %llu",
				  vi->nid);
			DBG_BUGON(1);
			return -EFSCORRUPTED;
		}
		map->m_flags |= EROFS_MAP_META;
	} else {
		erofs_err(sb, "internal error @ nid: %llu (size %llu), m_la 0x%llx",
			  vi->nid, inode->i_size, map->m_la);
		DBG_BUGON(1);
		return -EIO;
	}
	return 0;
}

static int erofs_map_blocks(struct inode *inode, struct erofs_map_blocks *map)
{
	struct super_block *sb = inode->i_sb;
	struct erofs_inode *vi = EROFS_I(inode);
	struct erofs_inode_chunk_index *idx;
	struct erofs_buf buf = __EROFS_BUF_INITIALIZER;
	u64 chunknr;
	unsigned int unit;
	erofs_off_t pos;
	void *kaddr;
	int err = 0;

	trace_erofs_map_blocks_enter(inode, map, 0);
	if (map->m_la >= inode->i_size) {
		/* leave out-of-bound access unmapped */
		map->m_flags = 0;
		map->m_plen = 0;
		goto out;
	}

	if (vi->datalayout != EROFS_INODE_CHUNK_BASED) {
		err = erofs_map_blocks_flatmode(inode, map);
		goto out;
	}

	if (vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES)
		unit = sizeof(*idx);			/* chunk index */
	else
		unit = EROFS_BLOCK_MAP_ENTRY_SIZE;	/* block map */

	chunknr = map->m_la >> vi->chunkbits;
	pos = ALIGN(erofs_iloc(inode) + vi->inode_isize +
		    vi->xattr_isize, unit) + unit * chunknr;

	kaddr = erofs_read_metabuf(&buf, sb, erofs_blknr(sb, pos), EROFS_KMAP);
	if (IS_ERR(kaddr)) {
		err = PTR_ERR(kaddr);
		goto out;
	}
	map->m_la = chunknr << vi->chunkbits;
	map->m_plen = min_t(erofs_off_t, 1UL << vi->chunkbits,
			round_up(inode->i_size - map->m_la, sb->s_blocksize));

	/* handle block map */
	if (!(vi->chunkformat & EROFS_CHUNK_FORMAT_INDEXES)) {
		__le32 *blkaddr = kaddr + erofs_blkoff(sb, pos);

		if (le32_to_cpu(*blkaddr) == EROFS_NULL_ADDR) {
			map->m_flags = 0;
		} else {
			map->m_pa = erofs_pos(sb, le32_to_cpu(*blkaddr));
			map->m_flags = EROFS_MAP_MAPPED;
		}
		goto out_unlock;
	}
	/* parse chunk indexes */
	idx = kaddr + erofs_blkoff(sb, pos);
	switch (le32_to_cpu(idx->blkaddr)) {
	case EROFS_NULL_ADDR:
		map->m_flags = 0;
		break;
	default:
		/* only one device is supported for now */
		if (idx->device_id) {
			erofs_err(sb, "invalid device id %u @ %llu for nid %llu",
				  le16_to_cpu(idx->device_id),
				  chunknr, vi->nid);
			err = -EFSCORRUPTED;
			goto out_unlock;
		}
		map->m_pa = erofs_pos(sb, le32_to_cpu(idx->blkaddr));
		map->m_flags = EROFS_MAP_MAPPED;
		break;
	}
out_unlock:
	erofs_put_metabuf(&buf);
out:
	if (!err)
		map->m_llen = map->m_plen;
	trace_erofs_map_blocks_exit(inode, map, 0, err);
	return err;
}

static inline struct bio *erofs_read_raw_page(struct bio *bio,
					      struct address_space *mapping,
					      struct page *page,
					      erofs_off_t *last_block,
					      unsigned int nblocks,
					      bool ra)
{
	struct inode *const inode = mapping->host;
	struct super_block *const sb = inode->i_sb;
	erofs_off_t current_block = (erofs_off_t)page->index;
	int err;

	DBG_BUGON(!nblocks);

	if (PageUptodate(page)) {
		err = 0;
		goto has_updated;
	}

	/* note that for readpage case, bio also equals to NULL */
	if (bio &&
	    /* not continuous */
	    *last_block + 1 != current_block) {
submit_bio_retry:
		submit_bio(bio);
		bio = NULL;
	}

	if (!bio) {
		struct erofs_map_blocks map = {
			.m_la = erofs_pos(sb, current_block),
		};
		erofs_blk_t blknr;
		unsigned int blkoff;

		err = erofs_map_blocks(inode, &map);
		if (err)
			goto err_out;

		/* zero out the holed page */
		if (!(map.m_flags & EROFS_MAP_MAPPED)) {
			zero_user_segment(page, 0, PAGE_SIZE);
			SetPageUptodate(page);

			/* imply err = 0, see erofs_map_blocks */
			goto has_updated;
		}

		/* for RAW access mode, m_plen must be equal to m_llen */
		DBG_BUGON(map.m_plen != map.m_llen);

		blknr = erofs_blknr(sb, map.m_pa);
		blkoff = erofs_blkoff(sb, map.m_pa);

		/* deal with inline page */
		if (map.m_flags & EROFS_MAP_META) {
			void *vsrc, *vto;
			struct page *ipage;

			DBG_BUGON(map.m_plen > PAGE_SIZE);

			ipage = erofs_get_meta_page(inode->i_sb, blknr);

			if (IS_ERR(ipage)) {
				err = PTR_ERR(ipage);
				goto err_out;
			}

			vsrc = kmap_atomic(ipage);
			vto = kmap_atomic(page);
			memcpy(vto, vsrc + blkoff, map.m_plen);
			memset(vto + map.m_plen, 0, PAGE_SIZE - map.m_plen);
			kunmap_atomic(vto);
			kunmap_atomic(vsrc);
			flush_dcache_page(page);

			SetPageUptodate(page);
			/* TODO: could we unlock the page earlier? */
			unlock_page(ipage);
			put_page(ipage);

			/* imply err = 0, see erofs_map_blocks */
			goto has_updated;
		}

		/* pa must be block-aligned for raw reading */
		DBG_BUGON(erofs_blkoff(sb, map.m_pa));

		/* max # of continuous pages */
		if (nblocks > DIV_ROUND_UP(map.m_plen, PAGE_SIZE))
			nblocks = DIV_ROUND_UP(map.m_plen, PAGE_SIZE);
		if (nblocks > BIO_MAX_PAGES)
			nblocks = BIO_MAX_PAGES;

		bio = bio_alloc(GFP_NOIO, nblocks);

		bio->bi_end_io = erofs_readendio;
		bio_set_dev(bio, sb->s_bdev);
		bio->bi_iter.bi_sector = (sector_t)blknr <<
			(sb->s_blocksize_bits - 9);
		bio->bi_opf = REQ_OP_READ | (ra ? REQ_RAHEAD : 0);
	}

	err = bio_add_page(bio, page, PAGE_SIZE, 0);
	/* out of the extent or bio is full */
	if (err < PAGE_SIZE)
		goto submit_bio_retry;

	*last_block = current_block;

	/* shift in advance in case of it followed by too many gaps */
	if (bio->bi_iter.bi_size >= bio->bi_max_vecs * PAGE_SIZE) {
		/* err should reassign to 0 after submitting */
		err = 0;
		goto submit_bio_out;
	}

	return bio;

err_out:
	/* for sync reading, set page error immediately */
	if (!ra) {
		SetPageError(page);
		ClearPageUptodate(page);
	}
has_updated:
	unlock_page(page);

	/* if updated manually, continuous pages has a gap */
	if (bio)
submit_bio_out:
		submit_bio(bio);
	return err ? ERR_PTR(err) : NULL;
}

/*
 * since we dont have write or truncate flows, so no inode
 * locking needs to be held at the moment.
 */
static int erofs_raw_access_readpage(struct file *file, struct page *page)
{
	erofs_off_t uninitialized_var(last_block);
	struct bio *bio;

	trace_erofs_readpage(page, true);

	bio = erofs_read_raw_page(NULL, page->mapping,
				  page, &last_block, 1, false);

	if (IS_ERR(bio))
		return PTR_ERR(bio);

	DBG_BUGON(bio);	/* since we have only one bio -- must be NULL */
	return 0;
}

static void erofs_raw_access_readahead(struct readahead_control *rac)
{
	erofs_off_t uninitialized_var(last_block);
	struct bio *bio = NULL;
	struct page *page;

	trace_erofs_readpages(rac->mapping->host, readahead_index(rac),
			readahead_count(rac), true);

	while ((page = readahead_page(rac))) {
		prefetchw(&page->flags);

		bio = erofs_read_raw_page(bio, rac->mapping, page, &last_block,
				readahead_count(rac), true);

		/* all the page errors are ignored when readahead */
		if (IS_ERR(bio)) {
			pr_err("%s, readahead error at page %lu of nid %llu\n",
			       __func__, page->index,
			       EROFS_I(rac->mapping->host)->nid);

			bio = NULL;
		}

		put_page(page);
	}

	/* the rare case (end in gaps) */
	if (bio)
		submit_bio(bio);
}

static sector_t erofs_bmap(struct address_space *mapping, sector_t block)
{
	struct inode *inode = mapping->host;
	struct erofs_map_blocks map = {
		.m_la = erofs_pos(inode->i_sb, block),
	};

	if (EROFS_I(inode)->datalayout == EROFS_INODE_FLAT_INLINE) {
		erofs_blk_t blks = i_size_read(inode) >>
				   inode->i_sb->s_blocksize_bits;

		if (block >> (inode->i_sb->s_blocksize_bits - 9) >= blks)
			return 0;
	}

	if (!erofs_map_blocks(inode, &map))
		return erofs_blknr(inode->i_sb, map.m_pa);

	return 0;
}

/* for uncompressed (aligned) files and raw access for other files */
const struct address_space_operations erofs_raw_access_aops = {
	.readpage = erofs_raw_access_readpage,
	.readahead = erofs_raw_access_readahead,
	.bmap = erofs_bmap,
};

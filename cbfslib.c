#ifndef CBFS
#define CBFS
#include "cbfslib.h"
#endif //CLASS_NAME_H_
#include <assert.h>
#include "xdr.h"
#include <string.h>

#define unused __attribute__((unused))
#define CBFS_FILE_ATTR_TAG_COMPRESSION 0x42435a4c
#define CBFS_FILE_ATTR_TAG_UNUSED 0
#define CBFS_FILE_ATTR_TAG_UNUSED2 0xffffffff
#define CBFS_COMPONENT_DELETED 0
#define CBFS_COMPONENT_NULL 0xFFFFFFFF
#define CBFS_CONTENT_DEFAULT_VALUE	(-1)
#define MAX_CBFS_FILE_HEADER_BUFFER 1024
#define CBFS_FILENAME_ALIGN	(16)

extern struct xdr xdr_be;

struct cbfs_file *cbfs_find_next_entry(struct cbfs_image *image,
				       struct cbfs_file *entry);
struct cbfs_file *cbfs_find_first_entry(struct cbfs_image *image);
uint32_t cbfs_get_entry_addr(struct cbfs_image *image, struct cbfs_file *entry);
struct cbfs_file *cbfs_get_entry(struct cbfs_image *image, const char *name);

typedef int (*decomp_func_ptr) (char *in, int in_len, char *out, int out_len,
				size_t *actual_size);

struct cbfs_file *cbfs_create_file_header(int type, size_t len,
	const char *name);

static inline uint32_t align_up(uint32_t value, uint32_t align)
{
	if (value % align)
		value += align - (value % align);
	return value;
}

size_t cbfs_calculate_file_header_size(const char *name)
{
	return (sizeof(struct cbfs_file) +
		align_up(strlen(name) + 1, CBFS_FILENAME_ALIGN));
}

struct cbfs_file *cbfs_create_file_header(int type,
			    size_t len, const char *name)
{
	int8_t reserved_memory[MAX_CBFS_FILE_HEADER_BUFFER];
	struct cbfs_file *entry = (void *) &reserved_memory[0]; //malloc(MAX_CBFS_FILE_HEADER_BUFFER);
	memset(entry, CBFS_CONTENT_DEFAULT_VALUE, MAX_CBFS_FILE_HEADER_BUFFER);
	memcpy(entry->magic, CBFS_FILE_MAGIC, sizeof(entry->magic));
	entry->type = htonl(type);
	entry->len = htonl(len);
	entry->attributes_offset = 0;
	entry->offset = htonl(cbfs_calculate_file_header_size(name));
	memset(entry->filename, 0, ntohl(entry->offset) - sizeof(*entry));
	strcpy(entry->filename, name);
	return entry;
}

struct cbfs_file_attribute *cbfs_file_first_attr(struct cbfs_file *file)
{
	/* attributes_offset should be 0 when there is no attribute, but all
	 * values that point into the cbfs_file header are invalid, too. */
	if (ntohl(file->attributes_offset) <= sizeof(*file))
		return NULL;

	/* There needs to be enough space for the file header and one
	 * attribute header for this to make sense. */
	if (ntohl(file->offset) <=
		sizeof(*file) + sizeof(struct cbfs_file_attribute))
		return NULL;

	return (struct cbfs_file_attribute *)
	    (((uint8_t *)file) + ntohl(file->attributes_offset));
}

struct cbfs_file_attribute *cbfs_file_next_attr(struct cbfs_file *file,
	struct cbfs_file_attribute *attr)
{
	/* ex falso sequitur quodlibet */
	if (attr == NULL)
		return NULL;

	/* Is there enough space for another attribute? */
	if ((uint8_t *)attr + ntohl(attr->len) +
		sizeof(struct cbfs_file_attribute) >=
		(uint8_t *)file + ntohl(file->offset))
		return NULL;

	struct cbfs_file_attribute *next = (struct cbfs_file_attribute *)
		(((uint8_t *)attr) + ntohl(attr->len));
	/* If any, "unused" attributes must come last. */
	if (ntohl(next->tag) == CBFS_FILE_ATTR_TAG_UNUSED)
		return NULL;
	if (ntohl(next->tag) == CBFS_FILE_ATTR_TAG_UNUSED2)
		return NULL;

	return next;
}

uint32_t cbfs_get_entry_addr(struct cbfs_image *image, struct cbfs_file *entry)
{
	assert(image && image->buffer.data && entry);
	return (int32_t)((char *)entry - image->buffer.data);
}

static inline void buffer_splice(struct buffer *dest, const struct buffer *src,
                                 size_t offset, size_t size)
{
	dest->name = src->name;
	dest->data = src->data + offset;
	dest->offset = src->offset + offset;
	dest->size = size;
}

static inline void buffer_clone(struct buffer *dest, const struct buffer *src)
{
	buffer_splice(dest, src, 0, src->size);
}

static inline bool buffer_check_magic(const struct buffer *b, const char *magic,
							size_t magic_len)
{
	assert(magic);
	return b && b->size >= magic_len &&
					memcmp(b->data, magic, magic_len) == 0;
}

int cbfs_is_valid_cbfs(struct cbfs_image *image)
{
	return buffer_check_magic(&image->buffer, CBFS_FILE_MAGIC,
						strlen(CBFS_FILE_MAGIC));
}

static int cbfs_header_valid(struct cbfs_header *header)
{
	if ((ntohl(header->magic) == CBFS_HEADER_MAGIC) &&
	    ((ntohl(header->version) == CBFS_HEADER_VERSION1) ||
	     (ntohl(header->version) == CBFS_HEADER_VERSION2)) &&
	    (ntohl(header->offset) < ntohl(header->romsize)))
		return 1;
	return 0;
}


struct cbfs_header *cbfs_find_header(char *data, size_t size,
				     uint32_t forced_offset)
{
	size_t offset;
	int found = 0;
	int32_t rel_offset;
	struct cbfs_header *header, *result = NULL;

	if (forced_offset < (size - sizeof(struct cbfs_header))) {
		/* Check if the forced header is valid. */
		header = (struct cbfs_header *)(data + forced_offset);
		if (cbfs_header_valid(header))
			return header;
		return NULL;
	}

	// Try finding relative offset of master header at end of file first.
	rel_offset = *(int32_t *)(data + size - sizeof(int32_t));
	offset = size + rel_offset;
	//DEBUG("relative offset: %#zx(-%#zx), offset: %#zx\n",
	//      (size_t)rel_offset, (size_t)-rel_offset, offset);

	if (offset >= size - sizeof(*header) ||
	    !cbfs_header_valid((struct cbfs_header *)(data + offset))) {
		// Some use cases append non-CBFS data to the end of the ROM.
		//DEBUG("relative offset seems wrong, scanning whole image...\n");
		offset = 0;
	}

	for (; offset + sizeof(*header) < size; offset++) {
		header = (struct cbfs_header *)(data + offset);
		if (!cbfs_header_valid(header))
			continue;
		if (!found++)
			result = header;
	}
	if (found > 1)
        printf("Warning guacho, mas de un header found\n");
		// Top-aligned images usually have a working relative offset
		// field, so this is more likely to happen on bottom-aligned
		// ones (where the first header is the "outermost" one)
		//WARN("Multiple (%d) CBFS headers found, using the first one.\n",
		//       found);
	return result;
}

void cbfs_get_header(struct cbfs_header *header, void *src)
{
	struct buffer outheader;

	outheader.data = src;	/* We're not modifying the data */
	outheader.size = 0;

	header->magic = xdr_be.get32(&outheader);
	header->version = xdr_be.get32(&outheader);
	header->romsize = xdr_be.get32(&outheader);
	header->bootblocksize = xdr_be.get32(&outheader);
	header->align = xdr_be.get32(&outheader);
	header->offset = xdr_be.get32(&outheader);
	header->architecture = xdr_be.get32(&outheader);
}

struct cbfs_file *cbfs_get_entry(struct cbfs_image *image, const char *name)
{
	struct cbfs_file *entry;
	for (entry = cbfs_find_first_entry(image);
	     entry && cbfs_is_valid_entry(image, entry);
	     entry = cbfs_find_next_entry(image, entry)) {
		if (strcasecmp(entry->filename, name) == 0) {
			//DEBUG("cbfs_get_entry: found %s\n", name);
			return entry;
		}

	}
	return NULL;
}

int cbfs_is_legacy_cbfs(struct cbfs_image *image)
{
	return image->has_header;
}

static inline size_t buffer_offset(const struct buffer *b)
{
	return b->offset;
}

static inline void *buffer_get(const struct buffer *b)
{
	return b->data;
}


static inline void *buffer_get_original_backing(const struct buffer *b)
{
	if (!b)
		return NULL;
	return buffer_get(b) - buffer_offset(b);
}

struct cbfs_file *cbfs_find_first_entry(struct cbfs_image *image)
{
	assert(image);
	if (image->has_header)
		/* header.offset is relative to start of flash, not
		 * start of region, so use it with the full image.
		 */
		return (struct cbfs_file *)
			(buffer_get_original_backing(&image->buffer) +
			image->header.offset);
	else
		return (struct cbfs_file *)buffer_get(&image->buffer);
}

static inline void buffer_seek(struct buffer *b, size_t size)
{
	b->offset += size;
	b->size -= size;
	b->data += size;
}


int cbfs_is_valid_entry(struct cbfs_image *image, struct cbfs_file *entry)
{
	uint32_t offset = cbfs_get_entry_addr(image, entry);

	if (offset >= image->buffer.size)
		return 0;

	struct buffer entry_data;
	buffer_clone(&entry_data, &image->buffer);
	buffer_seek(&entry_data, offset);
	return buffer_check_magic(&entry_data, CBFS_FILE_MAGIC,
						strlen(CBFS_FILE_MAGIC));
}


struct cbfs_file *cbfs_find_next_entry(struct cbfs_image *image,
				       struct cbfs_file *entry)
{
	uint32_t addr = cbfs_get_entry_addr(image, entry);
	int align = image->has_header ? image->header.align :
							CBFS_ENTRY_ALIGNMENT;
	assert(entry && cbfs_is_valid_entry(image, entry));
	addr += ntohl(entry->offset) + ntohl(entry->len);
	addr = align_up(addr, align);
	return (struct cbfs_file *)(image->buffer.data + addr);
}

static int cbfs_fix_legacy_size(struct cbfs_image *image, char *hdr_loc)
{
	assert(image);
	assert(cbfs_is_legacy_cbfs(image));
	// A bug in old cbfstool may produce extra few bytes (by alignment) and
	// cause cbfstool to overwrite things after free space -- which is
	// usually CBFS header on x86. We need to workaround that.
	// Except when we run across a file that contains the actual header,
	// in which case this image is a safe, new-style
	// `cbfstool add-master-header` based image.

	struct cbfs_file *entry, *first = NULL, *last = NULL;
	for (first = entry = cbfs_find_first_entry(image);
	     entry && cbfs_is_valid_entry(image, entry);
	     entry = cbfs_find_next_entry(image, entry)) {
		/* Is the header guarded by a CBFS file entry? Then exit */
		if (((char *)entry) + ntohl(entry->offset) == hdr_loc) {
			return 0;
		}
		last = entry;
	}
	if ((char *)first < (char *)hdr_loc &&
	    (char *)entry > (char *)hdr_loc) {
		//WARN("CBFS image was created with old cbfstool with size bug. "
		//     "Fixing size in last entry...\n");
		last->len = htonl(ntohl(last->len) - image->header.align);
		//DEBUG("Last entry has been changed from 0x%x to 0x%x.\n",
		//      cbfs_get_entry_addr(image, entry),
		//      cbfs_get_entry_addr(image,
	    //				  cbfs_find_next_entry(image, last)));
	}
	return 0;
}

int cbfs_image_from_buffer(struct cbfs_image *out, struct buffer *in,
			   uint32_t offset)
{
	assert(out);
	assert(in);
	assert(in->data);

	buffer_clone(&out->buffer, in);
	out->has_header = false;

	if (cbfs_is_valid_cbfs(out)) {
		return 0;
	}

	void *header_loc = cbfs_find_header(in->data, in->size, offset);
	if (header_loc) {
		cbfs_get_header(&out->header, header_loc);
		out->has_header = true;
		cbfs_fix_legacy_size(out, header_loc);
		return 0;
	} else if (offset != ~0u) {
        printf("Algo con el switch CBFS.\n");
		//ERROR("The -H switch is only valid on legacy images having CBFS master headers.\n");
		return 1;
	}
	//ERROR("Selected image region is not a valid CBFS.\n");
    printf("Selected image region is not a valid CBFS.\n");
	return 1;
}

int cbfs_create_empty_entry(struct cbfs_file *entry, int type,
			    size_t len, const char *name)
{
	struct cbfs_file *tmp = cbfs_create_file_header(type, len, name);
	memcpy(entry, tmp, ntohl(tmp->offset));
	//free(tmp);
	memset(CBFS_SUBHEADER(entry), CBFS_CONTENT_DEFAULT_VALUE, len);
	return 0;
}

int cbfs_merge_empty_entry(struct cbfs_image *image, struct cbfs_file *entry,
			   unused void *arg)
{
	struct cbfs_file *next;
	uint8_t *name;
	uint32_t type, addr, last_addr;

	type = ntohl(entry->type);
	if (type == CBFS_COMPONENT_DELETED) {
		// Ready to be recycled.
		type = CBFS_COMPONENT_NULL;
		entry->type = htonl(type);
		// Place NUL byte as first byte of name to be viewed as "empty".
		name = (void *)&entry[1];
		*name = '\0';
	}
	if (type != CBFS_COMPONENT_NULL)
		return 0;

	next = cbfs_find_next_entry(image, entry);

	while (next && cbfs_is_valid_entry(image, next)) {
		type = ntohl(next->type);
		if (type == CBFS_COMPONENT_DELETED) {
			type = CBFS_COMPONENT_NULL;
			next->type = htonl(type);
		}
		if (type != CBFS_COMPONENT_NULL)
			return 0;

		addr = cbfs_get_entry_addr(image, entry);
		last_addr = cbfs_get_entry_addr(
				image, cbfs_find_next_entry(image, next));

		// Now, we find two deleted/empty entries; try to merge now.
		//DEBUG("join_empty_entry: combine 0x%x+0x%x and 0x%x+0x%x.\n",
		//      cbfs_get_entry_addr(image, entry), ntohl(entry->len),
		//      cbfs_get_entry_addr(image, next), ntohl(next->len));
		cbfs_create_empty_entry(entry, CBFS_COMPONENT_NULL,
					(last_addr - addr -
					 cbfs_calculate_file_header_size("")),
					"");
		//DEBUG("new empty entry: length=0x%x\n", ntohl(entry->len));
		next = cbfs_find_next_entry(image, entry);
	}
	return 0;
}


int cbfs_remove_entry(struct cbfs_image *image, const char *name)
{
	struct cbfs_file *entry;
	entry = cbfs_get_entry(image, name);
	if (!entry) {
		//ERROR("CBFS file %s not found.\n", name);
		return -1;
	}
	//DEBUG("cbfs_remove_entry: Removed %s @ 0x%x\n",
	      //entry->filename, cbfs_get_entry_addr(image, entry));
	entry->type = htonl(CBFS_COMPONENT_DELETED);
	cbfs_walk(image, cbfs_merge_empty_entry, NULL);
	return 0;
}

int cbfs_walk(struct cbfs_image *image, cbfs_entry_callback callback,
	      void *arg)
{
	int count = 0;
	struct cbfs_file *entry;
	for (entry = cbfs_find_first_entry(image);
	     entry && cbfs_is_valid_entry(image, entry);
	     entry = cbfs_find_next_entry(image, entry)) {
		count ++;
		if (callback(image, entry, arg) != 0)
			break;
	}
	return count;
}



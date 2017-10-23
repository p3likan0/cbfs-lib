#include <stdio.h>
#include "stdint.h"
#include <stddef.h>
#include <stdlib.h>
#include "stdbool.h"

#define CBFS_FILE_MAGIC "LARCHIVE"
#define CBFS_HEADER_MAGIC  0x4F524243
#define CBFS_HEADER_VERSION1 0x31313131
#define CBFS_HEADER_VERSION2 0x31313132
#define CBFS_ENTRY_ALIGNMENT 64
#define CBFS_SUBHEADER(_p) ( (void *) ((((uint8_t *) (_p)) + ntohl((_p)->offset))) )
#define __PACKED __attribute__((gcc_struct, packed))

struct cbfs_file_attr_compression {
	uint32_t tag;
	uint32_t len;
	/* whole file compression format. 0 if no compression. */
	uint32_t compression;
	uint32_t decompressed_size;
} __PACKED;

struct cbfs_file_attribute {
	uint32_t tag;
	/* len covers the whole structure, incl. tag and len */
	uint32_t len;
	uint8_t data[0];
} __PACKED;

struct buffer {
	char *name;
	char *data;
	size_t offset;
	size_t size;
};

struct cbfs_header {
	uint32_t magic;
	uint32_t version;
	uint32_t romsize;
	uint32_t bootblocksize;
	uint32_t align; /* hard coded to 64 byte */
	uint32_t offset;
	uint32_t architecture;	/* Version 2 */
	uint32_t pad[1];
} __PACKED;

struct cbfs_file {
	uint8_t magic[8];
	/* length of file data */
	uint32_t len;
	uint32_t type;
	/* offset to struct cbfs_file_attribute or 0 */
	uint32_t attributes_offset;
	/* length of header incl. variable data */
	uint32_t offset;
	char filename[];
} __PACKED;



struct cbfs_image {
	struct buffer buffer;
	/* An image has a header iff it's a legacy CBFS. */
	bool has_header;
	/* Only meaningful if has_header is selected. */
	struct cbfs_header header;
};

typedef int (*cbfs_entry_callback)(struct cbfs_image *image,
				   struct cbfs_file *file,
				   void *arg);

int cbfs_remove_entry(struct cbfs_image *image, const char *name);

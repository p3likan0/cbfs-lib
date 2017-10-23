#include <stdio.h>
#ifndef CBFS
#define CBFS
#include "cbfslib.h"
#endif 

#ifndef FIT
#define FIT
#include "fitlib.h"
#include "xdr.h"
#endif 
#include "md5.h"

extern struct xdr xdr_be;


#define CHUNK 4*1024*1024

struct cbfs_fileheader {
    uint8_t magic[8];
    uint32_t len;
    uint32_t type;
    uint32_t checksum;
    uint32_t offset;
} __PACKED;

int32_t get_entry_len(struct cbfs_file *entry) {
    struct buffer outheader;
	outheader.data = &entry->len;	/* We're not modifying the data */
	outheader.size = 0;
    return xdr_be.get32(&outheader);
}

int32_t get_entry_offset(struct cbfs_file *entry) {
    struct buffer outheader;
	outheader.data = &entry->offset;	/* We're not modifying the data */
	outheader.size = 0;
    return xdr_be.get32(&outheader);
}

int main(int argc, char* argv[]) {
    if( argc != 3 ){
        printf("Use: cbfslib romfile.rom file_to_get_address");
        return 1;
    }

    char buf[CHUNK];
    FILE *file;
    size_t nread;

    file = fopen(argv[1], "r");
    fread(buf, CHUNK, 1, file);

	struct buffer buffer;
    buffer.offset = 0;
	buffer.size = CHUNK;
	buffer.name = strdup("BIOS");
	buffer.data = buf;

	struct cbfs_file *entry;
    struct cbfs_image image;


	if (cbfs_image_from_buffer(&image, &buffer, ~0)){
        printf("Cant read .rom\n");
		return 1;
    }else{
        entry = cbfs_get_entry(&image, argv[2]);
	    if (entry == NULL) {
        printf("Can not find entry\n");
	    }
       	cbfs_remove_entry(&image, argv[2]);

        MD5_CTX ctx;
        MD5Init(&ctx);
        MD5Update(&ctx, buf, CHUNK);
        MD5Final(&ctx);

        printf("Md5 sum is \n");
        for(int i=0; i<16; i++){
            printf("%x", ctx.digest[i]);
        }
    }

  return 0;
}


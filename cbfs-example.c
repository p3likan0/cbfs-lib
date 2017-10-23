#include <stdio.h>
#ifndef CBFS
#define CBFS
#include "cbfslib.h"
#endif 

#ifndef FIT
#define FIT
#include "fitlib.h"
#endif 

#define CHUNK 4*1024*1024

struct cbfs_fileheader {
    uint8_t magic[8];
    uint32_t len;
    uint32_t type;
    uint32_t checksum;
    uint32_t offset;
} __PACKED;

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
	buffer.size = 4*1024*1024;
	buffer.name = strdup("BIOS");
	buffer.data = buf;

	struct cbfs_file *entry;
    struct cbfs_image image;


	if (cbfs_image_from_buffer(&image, &buffer, ~0)){
        printf("Cant read .rom\n");
		return 1;
    }else{
	    if ((entry = cbfs_get_entry(&image, argv[2])) == NULL) {
        printf("Can not find entry\n");
	    }

        int32_t config_file_address = cbfs_get_entry_addr(&image, entry);
        printf("Found %s in address: %x\n", argv[2], config_file_address);
    }

  return 0;
}


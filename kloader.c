/*
 * Copyright 2014, winocm. <winocm@icloud.com>
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * $Id$
 */
/*
 * kloader
 * Requires: kernel patch for tfp0
 * Supports: armv7 iOS 4.0 - 9.3.5
 *           arm64 iOS 7.0 - 8.4.1
 */

#include <stdio.h>
#include <signal.h>
#include <notify.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <sys/sysctl.h>
#include <CoreFoundation/CoreFoundation.h>

extern mach_port_t IOPMFindPowerManagement(mach_port_t);
extern kern_return_t IOPMSchedulePowerEvent(CFDateRef time_to_wake, CFStringRef my_id, CFStringRef type);
extern kern_return_t IOPMSleepSystem(mach_port_t);

#define KERNEL_DUMP_SIZE 0xd00000
#define CHUNK_SIZE 2048
#define SLEEP_DELAY 2.0
#define kIOPMSystemPowerStateNotify "com.apple.powermanagement.systempowerstate"
#define kIOPMSettingDebugWakeRelativeKey "WakeRelativeToSleep"

#ifdef __arm64__
#define IMAGE_OFFSET 0x2000
#define MACHO_HEADER_MAGIC MH_MAGIC_64
#define KERNEL_SEARCH_ADDRESS 0xffffff8000000000

static uint32_t arm64_branch_instruction(uintptr_t from, uintptr_t to) {
  return from > to ? 0x18000000 - (from - to) / 4 : 0x14000000 + (to - from) / 4;
}
#else
#define IMAGE_OFFSET 0x1000
#define MACHO_HEADER_MAGIC MH_MAGIC
#define KERNEL_SEARCH_ADDRESS 0x81200000
#endif

/* Buggy, but re-implemented because some old versions of iOS don't have memmem */
static void * buggy_memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
  if (haystack == NULL || haystacklen == 0 || needle == NULL || needlelen == 0) {
    printf("ERROR: Invalid arguments for buggy_memmem.\n");
    exit(1);
  }

  for (size_t i = 0; i < haystacklen; i++)
    if (*(uint8_t *)(haystack + i) == *(uint8_t *)needle && i + needlelen <= haystacklen && 0 == memcmp(((uint8_t *)haystack) + i, needle, needlelen))
      return (void *)(((uint8_t *)haystack) + i);

  return NULL;
}

static uintptr_t find_larm_init_tramp(uint8_t *kdata, size_t ksize) {
#ifdef __arm64__
  // B +0x4; MSR DAIFSET, #0xF
  const uint8_t search[]  = { /* ??, ??, ??, ??, ??, ??, ??, ?? */ 0x01, 0x00, 0x00, 0x14, 0xDF, 0x4F, 0x03, 0xD5 };
  void *ptr = buggy_memmem(kdata, ksize, search, sizeof(search));
  if (ptr)
    return ((uintptr_t)ptr) - 8 - ((uintptr_t)kdata);
#else
  // LDR LR, [PC, LR]; B +0x0; CPSID IF
  const uint8_t search[]  = { 0x0E, 0xE0, 0x9F, 0xE7, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
  void *ptr = buggy_memmem(kdata, ksize, search, sizeof(search));
  if (ptr)
    return ((uintptr_t)ptr) - ((uintptr_t)kdata);

  // LDR LR, [PC, #imm]; B +0x0; CPSID IF
  const uint8_t search2[] = { /* ??, ?? */ 0x9F, 0xE5, 0xFF, 0xFF, 0xFF, 0xEA, 0xC0, 0x00, 0x0C, 0xF1 };
  ptr = buggy_memmem(kdata, ksize, search2, sizeof(search2));
  if (ptr)
    return ((uintptr_t)ptr) - 2 - ((uintptr_t)kdata);
#endif

  printf("ERROR: Failed to locate larm_init_tramp.\n");
  exit(1);
}

static void hook_kernel_wakeup(task_t kernel_task, uintptr_t kernel_base, uint8_t *kernel_dump, uintptr_t gPhysBase, uintptr_t load_address) {
  uintptr_t larm_init_tramp = kernel_base + IMAGE_OFFSET + find_larm_init_tramp(kernel_dump, KERNEL_DUMP_SIZE);
  printf("larm_init_tramp: 0x%lx\n", larm_init_tramp);

#ifdef __arm64__
  uint32_t expected_page_offset = 0xC;

  if (larm_init_tramp % 0x1000 != expected_page_offset) {
    printf("ERROR: larm_init_tramp is not at +0x%x offset on a 0x1000 boundary.\n", expected_page_offset);
    exit(1);
  }

  // TODO: Make sure only NOP instructions are overwritten by shellcode.
  uint64_t shellcode[3] = { 0x5800007ed50041bf, 0xd503201fd65f03c0, load_address };
  uint32_t branch_back = arm64_branch_instruction(larm_init_tramp, larm_init_tramp - expected_page_offset - sizeof(shellcode));
  vm_write(kernel_task, larm_init_tramp, (vm_offset_t)&branch_back, sizeof(branch_back));
  vm_write(kernel_task, larm_init_tramp - expected_page_offset - sizeof(shellcode), (vm_offset_t)&shellcode, sizeof(shellcode));
#else
  uint32_t shellcode[2] = { 0xe51ff004, load_address };
  vm_write(kernel_task, larm_init_tramp, (vm_offset_t)&shellcode, sizeof(shellcode));
#endif
}

static int get_cpid() {
  size_t size;
  sysctlbyname("kern.version", NULL, &size, NULL, 0);
  char *kern_version = malloc(size);
  if (sysctlbyname("kern.version", kern_version, &size, NULL, 0) == -1) {
    printf("ERROR: Failed to get kern.version sysctl.\n");
    exit(1);
  }
  printf("kern.version: %s\n", kern_version);

  uint32_t cpid = -1;
  if (strcasestr(kern_version, "S5L8920X")) {
    cpid = 0x8920;
  } else if (strcasestr(kern_version, "S5L8922X")) {
    cpid = 0x8922;
  } else if (strcasestr(kern_version, "S5L8930X")) {
    cpid = 0x8930;
  } else if (strcasestr(kern_version, "S5L8940X")) {
    cpid = 0x8940;
  } else if (strcasestr(kern_version, "S5L8942X")) {
    cpid = 0x8942;
  } else if (strcasestr(kern_version, "S5L8945X")) {
    cpid = 0x8945;
  } else if (strcasestr(kern_version, "S5L8947X")) {
    cpid = 0x8947;
  } else if (strcasestr(kern_version, "S5L8950X")) {
    cpid = 0x8950;
  } else if (strcasestr(kern_version, "S5L8955X")) {
    cpid = 0x8955;
  } else if (strcasestr(kern_version, "S5L8960X")) {
    cpid = 0x8960;
  } else if (strcasestr(kern_version, "T7000")) {
    cpid = 0x7000;
  } else if (strcasestr(kern_version, "T7001")) {
    cpid = 0x7001;
  } else if (strcasestr(kern_version, "S7002")) {
    cpid = 0x7002;
  } else if (strcasestr(kern_version, "S8000")) {
    cpid = 0x8000;
  } else if (strcasestr(kern_version, "S8001")) {
    cpid = 0x8001;
  } else if (strcasestr(kern_version, "T8002")) {
    cpid = 0x8002;
  } else if (strcasestr(kern_version, "S8003")) {
    cpid = 0x8003;
  } else if (strcasestr(kern_version, "T8010")) {
    cpid = 0x8010;
  } else if (strcasestr(kern_version, "T8011")) {
    cpid = 0x8011;
  } else {
    printf("ERROR: Failed to recognize chip from kern.version.\n");
    exit(1);
  }

  free(kern_version);
  return cpid;
}

static task_t get_kernel_task() {
  task_t kernel_task;
  if (KERN_SUCCESS == task_for_pid(mach_task_self(), 0, &kernel_task))
    return kernel_task;

  printf("ERROR: task_for_pid 0 failed.\n");
  exit(1);
}

static vm_address_t get_kernel_base(task_t kernel_task) {
  vm_region_submap_info_data_64_t info;
  vm_size_t size;
  mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
  unsigned int depth = 0;
  uintptr_t addr = KERNEL_SEARCH_ADDRESS;

  while (1) {
    if (KERN_SUCCESS != vm_region_recurse_64(kernel_task, (vm_address_t *)&addr, &size, &depth, (vm_region_info_t) &info, &info_count))
      break;
    if (size > 1024 * 1024 * 1024) {
      /*
       * https://code.google.com/p/iphone-dataprotection/
       * hax, sometimes on iOS7 kernel starts at +0x200000 in the 1Gb region
       */
      pointer_t buf;
      mach_msg_type_number_t sz = 0;
      addr += 0x200000;
      vm_read(kernel_task, addr + IMAGE_OFFSET, 512, &buf, &sz);
      if (*((uint32_t *)buf) != MACHO_HEADER_MAGIC) {
        addr -= 0x200000;
        vm_read(kernel_task, addr + IMAGE_OFFSET, 512, &buf, &sz);
        if (*((uint32_t*)buf) != MACHO_HEADER_MAGIC) {
          break;
        }
      }
      printf("kernel_base: 0x%08lx\n", (uintptr_t)addr);
      return addr;
    }
    addr += size;
  }

  printf("ERROR: Failed to find kernel base.\n");
  exit(1);
}

static void dump_kernel(task_t kernel_task, vm_address_t kernel_base, uint8_t *dest) {
  for (vm_address_t addr = kernel_base + IMAGE_OFFSET, e = 0; addr < kernel_base + KERNEL_DUMP_SIZE; addr += CHUNK_SIZE, e += CHUNK_SIZE) {
    pointer_t buf = 0;
    mach_msg_type_number_t sz = 0;
    vm_read(kernel_task, addr, CHUNK_SIZE, &buf, &sz);
    if (buf == 0 || sz == 0)
      continue;
    bcopy((uint8_t *)buf, dest + e, CHUNK_SIZE);
  }
}

static void load_image_to_memory(task_t kernel_task, vm_address_t load_address, const char *filename) {
  FILE *f = fopen(filename, "rb");
  if (!f) {
    printf("ERROR: Failed to open the image file.\n");
    exit(1);
  }

  fseek(f, 0, SEEK_END);
  int length = ftell(f);
  fseek(f, 0, SEEK_SET);

  uint8_t *image = malloc(length);
  if (!image) {
    printf("ERROR: Failed to allocate memory for image.\n");
    exit(1);
  }

  fread(image, length, 1, f);
  fclose(f);
  printf("Read image into buffer: %p length: %d\n", image, length);

  if (*(uint32_t *)image == 'Img3') {
    printf("ERROR: This is an IMG3 file. For now, only unpacked raw images are supported. IMG3 support is coming soon.\n");
    exit(1);
  }

  if (!strcmp((const char *)image + 7, "IM4P")) {
    printf("ERROR: This is an IM4P file. For now, only unpacked raw images are supported. IM4P support is coming soon.\n");
    exit(1);
  }

  for (vm_size_t i = 0; i < length; i += CHUNK_SIZE) {
    vm_size_t part_size = (length - i < CHUNK_SIZE) ? length - i : CHUNK_SIZE;
    if (KERN_SUCCESS != vm_write(kernel_task, load_address + i, (vm_offset_t)image + i, part_size)) {
      printf("ERROR: vm_write in load_image_to_memory failed.\n");
      exit(1);
    }
  }

  if (*(uint64_t *)image != 0x9100000090000000 && *(uint32_t *)image != 0xea00000e) {
    printf("This doesn't appear to be an ARM bootloader image. Continuing though.\n");
  }

  printf("Image information: %s\n", image + 0x200);
  printf("Image information: %s\n", image + 0x240);
  printf("Image information: %s\n", image + 0x280);

  free(image);
}

static void schedule_autowake_during_sleep_notification(CFTimeInterval autowake_delay) {
  int out_token;
  uint32_t status = notify_register_dispatch(kIOPMSystemPowerStateNotify, &out_token, dispatch_get_main_queue(), ^(int token) {
    CFDateRef date = CFDateCreate(0, CFAbsoluteTimeGetCurrent() + autowake_delay);
    kern_return_t kr = IOPMSchedulePowerEvent(date, NULL, CFSTR(kIOPMSettingDebugWakeRelativeKey));
    if (kr) {
      printf("ERROR: IOPMSchedulePowerEvent returned %x.\n", kr);
      exit(1);
    }
    /* Stop the runloop */
    CFRunLoopStop(CFRunLoopGetCurrent());
  });

  if (status != 0) {
    printf("ERROR: Failed to register for kIOPMSystemPowerStateNotify: %x\n", status);
    exit(1);
  }
}

static void request_sleep() {
  mach_port_t fb = IOPMFindPowerManagement(MACH_PORT_NULL);
  if (fb == MACH_PORT_NULL) {
    printf("ERROR: Failed to get PowerManagement root port.\n");
    exit(1);
  }

  for (int i = 0; i < 10; i++) {
    kern_return_t kr = IOPMSleepSystem(fb);
    if (!kr)
      return;

    printf("WARNING: IOPMSleepSystem returned %x. Trying again.\n", kr);
    sleep(1);
  }

  printf("ERROR: IOPMSleepSystem failed.\n");
  exit(1);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("usage: %s [loadfile]\n", argv[0]);
    printf("This will destroy the current running OS instance and fire up the loaded image.\n");
    printf("You have been warned.\n");
    exit(1);
  }

  uintptr_t gPhysBase = 0xdeadbeef;
  uintptr_t load_address = 0xdeadbeef;
  switch (get_cpid()) {

#ifndef __arm64__
    case 0x8920:
    case 0x8922:
      gPhysBase = 0x40000000;
      load_address = 0x4f000000;
      break;

    case 0x8930:
      gPhysBase = 0x40000000;
      load_address = 0x5f000000;
      break;

    case 0x8940:
    case 0x8942:
    case 0x8947:
      gPhysBase = 0x80000000;
      load_address = 0x9f000000;
      break;

    case 0x8945:
    case 0x8950:
    case 0x8955:
      gPhysBase = 0x80000000;
      load_address = 0xbf000000;
      break;
#endif

#ifdef __arm64__
    case 0x8960:
      gPhysBase = 0x800800000;
      load_address = 0x83d100000;
      break;

    case 0x7000:
      gPhysBase = 0x800e00000;
      load_address = 0x83eb00000;
      break;

    case 0x7001:
      gPhysBase = 0x800e00000;
      load_address = 0x85eb00000;
      break;
#endif

    default:
      printf("ERROR: Failed to recognize the chip.\n");
      exit(1);
  }

  /* Sync disks */
  for (int i = 0; i < 10; i++)
    sync();

  static uint8_t kernel_dump[KERNEL_DUMP_SIZE + IMAGE_OFFSET] = {0};
  task_t kernel_task = get_kernel_task();
  vm_address_t kernel_base = get_kernel_base(kernel_task);
  dump_kernel(kernel_task, kernel_base, kernel_dump);
  schedule_autowake_during_sleep_notification(SLEEP_DELAY);
  request_sleep();

  CFRunLoopRun();

  if (signal(SIGINT, SIG_IGN) != SIG_IGN)
    signal(SIGINT, SIG_IGN);

  load_image_to_memory(kernel_task, kernel_base - gPhysBase + load_address, argv[1]);
  hook_kernel_wakeup(kernel_task, kernel_base, kernel_dump, gPhysBase, load_address);

  /* Sync disks */
  for (int i = 0; i < 10; i++)
    sync();

  printf("Magic happening now. Device should wake up in %.1f seconds.\n", SLEEP_DELAY);

  return 0;
}

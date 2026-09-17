// Byte-level timeline of a ConPTY RUN: prints each read chunk with a timestamp.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "pty.h"
static double now_ms(void){static LARGE_INTEGER f;if(!f.QuadPart)QueryPerformanceFrequency(&f);LARGE_INTEGER c;QueryPerformanceCounter(&c);return c.QuadPart*1000.0/f.QuadPart;}
int main(int argc,char**argv){
  const char*shell=argc>1&&argv[1][0]?argv[1]:NULL; const char*script=argc>2?argv[2]:"true; echo __SENT__\n";
  int delay=argc>3?atoi(argv[3]):0;
  double t0=now_ms(); bridge_pty_t p; if(bridge_pty_spawn(&p,shell,NULL,1)){puts("spawn fail");return 1;}
  printf("%7.1f spawned\n",now_ms()-t0);
  if(delay){Sleep(delay);printf("%7.1f slept %d\n",now_ms()-t0,delay);}
  bridge_pty_write_all(&p,script,strlen(script)); printf("%7.1f wrote\n",now_ms()-t0);
  char buf[65536]; double dl=now_ms()+5000; size_t tot=0;
  while(now_ms()<dl){long n=bridge_pty_read(&p,buf,sizeof buf-1);if(n<=0){Sleep(1);continue;}buf[n]=0;
    printf("%7.1f read %ld: ",now_ms()-t0,n);for(long i=0;i<n&&i<2000;i++){unsigned char c=buf[i];if(c==27)printf("\\e");else if(c<32)printf("\\x%02x",c);else putchar(c);}puts("");
    tot+=n; if(strstr(buf,(argc>4?argv[4]:"__SENT__")))break;}
  printf("%7.1f done\n",now_ms()-t0); bridge_pty_signal(&p,9); bridge_pty_close(&p); return 0;}

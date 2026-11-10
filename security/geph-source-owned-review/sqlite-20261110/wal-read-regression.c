#include SOURCE_SQLITE
#include <stdio.h>
static int read_calls, read_amount, read_failure;
static sqlite3_int64 read_offset;
static int synthetic_read(sqlite3_file *f, void *out, int amount, sqlite3_int64 offset){
  (void)f;
  read_calls++; read_amount=amount; read_offset=offset;
  if(read_failure) return SQLITE_IOERR_READ;
  memset(out, 0x42, amount);
  return SQLITE_OK;
}
static const sqlite3_io_methods methods = {.iVersion=1,.xRead=synthetic_read};
static int run_case(int wal_page, int request, int io_failure){
  unsigned char buffer[65536];
  sqlite3_file file = {.pMethods=&methods};
  Wal wal = {0};
  wal.pWalFd=&file;
  wal.hdr.szPage = wal_page==65536 ? 1 : wal_page;
  memset(buffer, 0xA5, sizeof(buffer));
  read_calls=0; read_amount=0; read_offset=0; read_failure=io_failure;
  int rc=sqlite3WalReadFrame(&wal, 1, request, buffer);
  int expected_read=wal_page<request?wal_page:request;
  int expected_rc=io_failure?SQLITE_IOERR_READ:SQLITE_OK;
  if(rc!=expected_rc || read_calls!=1 || read_amount!=expected_read || read_offset!=56){
    fprintf(stderr,"read contract mismatch: %d/%d/%d/%lld\n",rc,read_calls,read_amount,(long long)read_offset); return 20;
  }
  for(int i=0;i<expected_read;i++){
    if(buffer[i]!=(io_failure?0xA5:0x42)){fprintf(stderr,"payload mismatch\n");return 21;}
  }
  int zeros=0, markers=0;
  for(int i=expected_read;i<request;i++) { zeros+=(buffer[i]==0); markers+=(buffer[i]==0xA5); }
  for(int i=request;i<65536;i++) if(buffer[i]!=0xA5){fprintf(stderr,"out-of-range write\n");return 22;}
  printf("{\"wal_page\":%d,\"requested\":%d,\"io_error\":%s,\"read_bytes\":%d,\"tail_zeros\":%d,\"tail_markers\":%d}\n",wal_page,request,io_failure?"true":"false",expected_read,zeros,markers);
  return 0;
}
int main(void){
  printf("{\"version\":\"%s\",\"source_id\":\"%s\"}\n",sqlite3_libversion(),sqlite3_sourceid());
  int inputs[][3]={{512,4096,0},{512,512,0},{4096,512,0},{65536,65536,0},{512,65536,0},{512,4096,1}};
  for(unsigned i=0;i<sizeof(inputs)/sizeof(inputs[0]);i++){
    int rc=run_case(inputs[i][0],inputs[i][1],inputs[i][2]); if(rc)return rc;
  }
  return 0;
}

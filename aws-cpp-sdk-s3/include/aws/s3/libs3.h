#ifndef AWS_LIBS3_H
#define AWS_LIBS3_H

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <iconv.h>

#if defined(__linux__)
#include <linux/types.h>
#endif

typedef void *S3_Client;

typedef enum
{
  private_1 = 1,
  public_read_1 = 2,
  public_read_write_1 = 3,
  authenticated_read_1 = 4,
} BucketACL;

/* bucket placement */
typedef enum
{
  not_set = 0,
  eu = 1,
  eu_west_1 = 2,
  us_west_1 = 3,
  us_west_2 = 4,
  ap_south_1 = 5,
  ap_southeast_1 = 6,
  ap_southeast_2 = 7,
  ap_northeast_1 = 8,
  sa_east_1 = 9,
  cn_north_1 = 10,
  eu_central_1 = 11,
  us_east_2 = 12,
} BucketLocationConstraint;

typedef void *list_marker_cursor_t;

typedef void *com_multipart_t;

//typedef unsigned int64_t uint64_t;

typedef struct {
  char* key;
  size_t key_len;
  
  char* val;
  size_t val_len;
} meta_info_t;

typedef struct {
  char* name;
  size_t name_len;
  
  meta_info_t* object_meta;
  size_t meta_len;
  size_t size;
  int64_t mtime;
  mode_t st_mode;
} object_info_t;

typedef struct {
  char* name;
  size_t name_len;
  
  meta_info_t* bucket_meta;
  size_t meta_len;
} bucket_info_t;

typedef struct {
  char* user_id;
  size_t user_id_len;
  
  char* acl;
  size_t acl_len;
} acl_info_t;

typedef void *S3_Connet_t;


int gbk_to_utf8(char * gbk_name, size_t source_len, char** utf_name, size_t* length)
{
  iconv_t cd = iconv_open("UTF-8", "GBK");
  if (cd==0) 
    return -1;
  iconv(cd, &gbk_name, &source_len, utf_name, length);
  iconv_close(cd);
  return 0;
}


/** free memery */

void Bucket_List_Free(bucket_info_t* buckets, size_t len);

void Object_List_Free(object_info_t* objects, size_t len);

void Bucket_Acl_Free(acl_info_t* acls, size_t len);

void Object_Info_Free(object_info_t object_info);

/** init connet */
int Init_Connet(S3_Connet_t* connet, S3_Client* s3_cli, 
                  int con_time, int req_time,
                  const char* access_key, const char* secret_key,
                  const char* endpoint);

int Check_Server(S3_Client s3_cli);

/** bucket feature */

int Create_Bucket(S3_Client s3_cli, const char* bucket_name, 
                          BucketACL b_acl, const char *location);
//                      BucketLocationConstraint b_location);

int Head_Bucket(S3_Client s3_cli, const char* bucket_name);

int Delete_Bucket(S3_Client s3_cli, const char *bucket_name);

int Get_Buckets_Size(S3_Client s3_cli, size_t *bkt_size);

int List_Buckets(S3_Client s3_cli, bucket_info_t *buckets, size_t b_size, 
                    size_t *real_size);

int Get_Bucket_Acl(S3_Client s3_cli, const char *bucket_name, 
                        acl_info_t *acls, const size_t len);

int Get_Bucket_Acl_Size(S3_Client s3_cli, const char *bucket_name, 
                              size_t *size);

int Put_Bucket_Acl(S3_Client s3_cli, const char *buckets, const acl_info_t acl);

/** object feature */

int Create_Object(S3_Client s3_cli, const char* bucket_name, 
                      const char* object_name);

int Put_Object(S3_Client s3_cli, const char* bucket_name, 
                 const char* object_name, const char* buf, 
                 size_t len, meta_info_t* meta, const size_t meta_size,
                 const char* acl);

/*
int Put_Object_File(S3_Client s3_cli, const char* bucket_name, 
                 const char* object_name, char* file,
                 meta_info_t* meta = NULL, const size_t meta_size = 0,
                 const char* acl = NULL);
*/

int Put_Object_Acl(S3_Client s3_cli, const char* bucket_name, 
                       const char* object_name, const char* acl);

int Get_Object_Acl(S3_Client s3_cli, const char* bucket_name, 
                       const char* object_name, char** acl, size_t* len);

int Get_Object_File(S3_Client s3_cli, const char* bucket_name, 
                       const char* object_name, const char* file_name,
                       char* version_id);


int Get_Object(S3_Client s3_cli, const char* bucket_name, 
                 const char* object_name, char* buf, size_t len,
                 int64_t off, int part_num, char* version_id);

int Put_Object_Metadata(S3_Client s3_cli, const char* bucket_name, 
                        const char* object_name, meta_info_t* meta, 
                        const size_t meta_size);

int Get_Object_Info(S3_Client s3_cli, const char * bucket_name,
                    const char * object_name, object_info_t* obj_info);

int List_Object(S3_Client s3_cli, const char *bucket_name,
                object_info_t *obj_info, size_t *info_len,
                const char *perfix, const char *delimiter,
                char **marker, int get_meta);

int Init_Multipart_Upload(S3_Client s3_cli, const char *bucket_name,
                          const char *object_name, char **upload_id,
                          com_multipart_t *com, meta_info_t* meta, 
                          const size_t meta_size, const char* acl);

int Upload_Part(S3_Client s3_cli, com_multipart_t com, const char *bucket_name, 
                   const char *object_name, const char *upload_id, int part_id, 
                   const char *buf,  size_t len);

int Complete_Multipart_Upload(S3_Client s3_cli, com_multipart_t com, 
                             const char *bucket_name, const char *object_name, 
                             const char *upload_id);

int Abort_Multipart_Upload(S3_Client s3_cli, const char *bucket_name, 
                           const char *object_name, const char *upload_id);

int Delete_Object(S3_Client s3_cli, const char *bucket_name, 
                     const char *object_name);

void Destroy_Upload(com_multipart_t com);


/**  destroy  */

void Destroy_Connet(S3_Connet_t connet, S3_Client s3_cli);


#ifdef __cplusplus
}
#endif

#endif



#include <aws/core/utils/Outcome.h>
#include <aws/core/auth/AWSAuthSigner.h>
#include <aws/core/client/CoreErrors.h>
#include <aws/core/client/RetryStrategy.h>
#include <aws/core/http/HttpClient.h>
#include <aws/core/http/HttpResponse.h>
#include <aws/core/http/HttpClientFactory.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/utils/xml/XmlSerializer.h>
#include <aws/core/utils/memory/stl/AWSStringStream.h>
#include <aws/core/utils/threading/Executor.h>
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProvider.h>
#include <aws/core/http/Scheme.h>
#include <aws/core/utils/memory/stl/AWSString.h>
#include <aws/s3/S3Client.h>
#include <aws/s3/S3Endpoint.h>
#include <aws/s3/S3ErrorMarshaller.h>
#include <aws/s3/model/AbortMultipartUploadRequest.h>
#include <aws/s3/model/CompleteMultipartUploadRequest.h>
#include <aws/s3/model/CopyObjectRequest.h>
#include <aws/s3/model/CreateBucketRequest.h>
#include <aws/s3/model/CreateMultipartUploadRequest.h>
#include <aws/s3/model/DeleteBucketRequest.h>
#include <aws/s3/model/DeleteBucketAnalyticsConfigurationRequest.h>
#include <aws/s3/model/DeleteBucketCorsRequest.h>
#include <aws/s3/model/DeleteBucketInventoryConfigurationRequest.h>
#include <aws/s3/model/DeleteBucketLifecycleRequest.h>
#include <aws/s3/model/DeleteBucketMetricsConfigurationRequest.h>
#include <aws/s3/model/DeleteBucketPolicyRequest.h>
#include <aws/s3/model/DeleteBucketReplicationRequest.h>
#include <aws/s3/model/DeleteBucketTaggingRequest.h>
#include <aws/s3/model/DeleteBucketWebsiteRequest.h>
#include <aws/s3/model/DeleteObjectRequest.h>
#include <aws/s3/model/DeleteObjectTaggingRequest.h>
#include <aws/s3/model/DeleteObjectsRequest.h>
#include <aws/s3/model/GetBucketAccelerateConfigurationRequest.h>
#include <aws/s3/model/GetBucketAclRequest.h>
#include <aws/s3/model/GetBucketAnalyticsConfigurationRequest.h>
#include <aws/s3/model/GetBucketCorsRequest.h>
#include <aws/s3/model/GetBucketInventoryConfigurationRequest.h>
#include <aws/s3/model/GetBucketLifecycleConfigurationRequest.h>
#include <aws/s3/model/GetBucketLocationRequest.h>
#include <aws/s3/model/GetBucketLoggingRequest.h>
#include <aws/s3/model/GetBucketMetricsConfigurationRequest.h>
#include <aws/s3/model/GetBucketNotificationConfigurationRequest.h>
#include <aws/s3/model/GetBucketPolicyRequest.h>
#include <aws/s3/model/GetBucketReplicationRequest.h>
#include <aws/s3/model/GetBucketRequestPaymentRequest.h>
#include <aws/s3/model/GetBucketTaggingRequest.h>
#include <aws/s3/model/GetBucketVersioningRequest.h>
#include <aws/s3/model/GetBucketWebsiteRequest.h>
#include <aws/s3/model/GetObjectRequest.h>
#include <aws/s3/model/GetObjectAclRequest.h>
#include <aws/s3/model/GetObjectTaggingRequest.h>
#include <aws/s3/model/GetObjectTorrentRequest.h>
#include <aws/s3/model/HeadBucketRequest.h>
#include <aws/s3/model/HeadObjectRequest.h>
#include <aws/s3/model/ListBucketAnalyticsConfigurationsRequest.h>
#include <aws/s3/model/ListBucketInventoryConfigurationsRequest.h>
#include <aws/s3/model/ListBucketMetricsConfigurationsRequest.h>
#include <aws/s3/model/ListMultipartUploadsRequest.h>
#include <aws/s3/model/ListObjectVersionsRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/ListObjectsV2Request.h>
#include <aws/s3/model/ListPartsRequest.h>
#include <aws/s3/model/PutBucketAccelerateConfigurationRequest.h>
#include <aws/s3/model/PutBucketAclRequest.h>
#include <aws/s3/model/PutBucketAnalyticsConfigurationRequest.h>
#include <aws/s3/model/PutBucketCorsRequest.h>
#include <aws/s3/model/PutBucketInventoryConfigurationRequest.h>
#include <aws/s3/model/PutBucketLifecycleConfigurationRequest.h>
#include <aws/s3/model/PutBucketLoggingRequest.h>
#include <aws/s3/model/PutBucketMetricsConfigurationRequest.h>
#include <aws/s3/model/PutBucketNotificationConfigurationRequest.h>
#include <aws/s3/model/PutBucketPolicyRequest.h>
#include <aws/s3/model/PutBucketReplicationRequest.h>
#include <aws/s3/model/PutBucketRequestPaymentRequest.h>
#include <aws/s3/model/PutBucketTaggingRequest.h>
#include <aws/s3/model/PutBucketVersioningRequest.h>
#include <aws/s3/model/PutBucketWebsiteRequest.h>
#include <aws/s3/model/PutObjectRequest.h>
#include <aws/s3/model/PutObjectAclRequest.h>
#include <aws/s3/model/PutObjectTaggingRequest.h>
#include <aws/s3/model/RestoreObjectRequest.h>
#include <aws/s3/model/UploadPartRequest.h>
#include <aws/s3/model/UploadPartCopyRequest.h>
#include <aws/s3/model/BucketCannedACL.h>
#include <aws/s3/model/PutBucketAclRequest.h>
#include <aws/s3/model/ListObjectsRequest.h>
#include <aws/s3/model/ListObjectsV2Request.h>
#include <aws/s3/model/CommonPrefix.h>

#include <aws/s3/libs3.h>
//#include "libs3.h"

Aws::String Get_Bucket_Acl_Type(BucketACL enumValue)
{
  switch(enumValue)
  {
    case BucketACL::private_1:
      return "private";
    case BucketACL::public_read_1:
      return "public-read";
    case BucketACL::public_read_write_1:
      return "public-read-write";
    case BucketACL::authenticated_read_1:
      return "authenticated-read";
    default:
      return "";
  }
}

/*
static void do_out_buffer(const std::string& outbl, char **outbuf, size_t *outbuflen)
{
  if (outbuf) {
    if (outbl.length() > 0) {
      *outbuf = (char *)malloc(sizeof(char) * outbl.length());
      memcpy(*outbuf, outbl.c_str(), outbl.length());
    } else {
      *outbuf = NULL;
    }
  }
  if (outbuflen)
    *outbuflen = outbl.length();
}
*/

static void do_out_buffer(const char* outbl, char **outbuf, size_t buflen)
{
  if (outbuf && outbl) {
    if (buflen > 0) {
      *outbuf = (char *)malloc(buflen+1);
      memcpy(*outbuf, outbl, buflen);
      (*outbuf)[buflen] = '\0';
    } else {
      *outbuf = NULL;
    }
  }
}

void meta_free(meta_info_t* metadata, size_t len)
{
  assert(metadata);
  for (unsigned int i = 0; i < len; i++)
  {
    if (metadata[i].key)
      free(metadata[i].key);
    if (metadata[i].val)
      free(metadata[i].val);
  }
}

extern "C" void Bucket_List_Free(bucket_info_t* buckets, size_t len)
{
  assert(buckets);
  for (unsigned int i = 0; i < len; i++)
  {
    if (buckets[i].meta_len)
      meta_free(buckets[i].bucket_meta, buckets[i].meta_len);
    if (buckets[i].name)
      free(buckets[i].name);
  }
}

extern "C" void Object_Info_Free(object_info_t object_info)
{

  if (object_info.meta_len)
    meta_free(object_info.object_meta, object_info.meta_len);
  if (object_info.name)
    free(object_info.name);
}

extern "C" void Object_List_Free(object_info_t* objects, size_t len)
{
  assert(objects);
	for (unsigned int i = 0; i < len; i++)
	{
    Object_Info_Free(objects[i]);
	}
}

extern "C" void Bucket_Acl_Free(acl_info_t* acls, size_t len)
{
  assert(acls);
  for (unsigned int i = 0; i < len; i++)
  {
    if (acls[i].acl)
      free(acls[i].acl);
    if (acls[i].user_id)
      free(acls[i].user_id);
  }
}

extern "C" int Init_Connet(S3_Connet_t* connet, S3_Client* s3_cli, 
                  int con_time, int req_time,
                  const char* access_key, const char* secret_key,
                  const char* endpoint)
{
  Aws::SDKOptions *options = new Aws::SDKOptions;
  Aws::InitAPI(*options);
  Aws::Client::ClientConfiguration config;
  Aws::Auth::AWSCredentials awscred;
  awscred.SetAWSAccessKeyId(access_key);
  awscred.SetAWSSecretKey(secret_key);
  config.endpointOverride = endpoint;
  config.verifySSL = true;
  config.scheme = Aws::Http::Scheme::HTTP;
  config.connectTimeoutMs = con_time * 1000;
  config.requestTimeoutMs = req_time * 1000;
  Aws::S3::S3Client *s3_client = new Aws::S3::S3Client(awscred, config);
  *connet = reinterpret_cast<S3_Connet_t>(options);
  *s3_cli = reinterpret_cast<S3_Client>(s3_client);
  return 0;
}

extern "C" void Destroy_Connet(S3_Connet_t connet, S3_Client s3_cli)
{
  Aws::SDKOptions *s3_connet = (Aws::SDKOptions *)connet;
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
    if (s3_connet)
    {
    Aws::ShutdownAPI(*s3_connet);
        delete s3_connet;
    }
    if (s3_client)
      delete s3_client;
}

extern "C" int Check_Server(S3_Client s3_cli)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  auto list_outcome = s3_client->ListBuckets();
  if (!list_outcome.IsSuccess())
    return (int)list_outcome.GetError().GetResponseCode();
  return 0;
}

/** bucket feature */


extern "C" int Create_Bucket(S3_Client s3_cli, const char* bucket_name, 
                      BucketACL b_acl , const char *location)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::CreateBucketRequest cre_b_req;
  int ret = 0;
  
  cre_b_req.SetACL(Aws::S3::Model::BucketCannedACLMapper::GetBucketCannedACLForName(
                 Get_Bucket_Acl_Type(b_acl)));
  
  cre_b_req.SetBucket(bucket_name);

  if (location) 
  {
    Aws::S3::Model::CreateBucketConfiguration bucketconf;
	bucketconf.SetLocationConstraintSpecial(location);
	cre_b_req.SetCreateBucketConfiguration(bucketconf);
  }
  
  auto cre_outcome = s3_client->CreateBucket(cre_b_req);
  if (!cre_outcome.IsSuccess()) 
    ret = (int)cre_outcome.GetError().GetResponseCode();

  return ret;
}

extern "C" int Head_Bucket(S3_Client s3_cli, const char* bucket_name)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::HeadBucketRequest head_req;
  head_req.SetBucket(bucket_name);

  auto head_outcome = s3_client->HeadBucket(head_req);
  if (!head_outcome.IsSuccess())
    return (int)head_outcome.GetError().GetResponseCode();
  return 0;
}

extern "C" int Delete_Bucket(S3_Client s3_cli, const char* bucket_name)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::DeleteBucketRequest del_b_req;
  int ret = 0;
  del_b_req.SetBucket(bucket_name);

  auto del_outcome = s3_client->DeleteBucket(del_b_req);
  if (!del_outcome.IsSuccess())
    ret = (int)del_outcome.GetError().GetResponseCode();

  return ret;
}

extern "C" int Get_Buckets_Size(S3_Client s3_cli, size_t *bkt_size)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  auto list_outcome = s3_client->ListBuckets();
  if (!list_outcome.IsSuccess())
    return (int)list_outcome.GetError().GetResponseCode();

  Aws::Vector<Aws::S3::Model::Bucket> bucket_list =
              list_outcome.GetResult().GetBuckets();
  *bkt_size = bucket_list.size();
  return 0;
}

extern "C" int List_Buckets(S3_Client s3_cli, bucket_info_t* buckets, 
                               size_t b_size, size_t *real_size)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  memset(buckets, 0, sizeof(bucket_info_t) * b_size);
	
  auto list_outcome = s3_client->ListBuckets();
  if (!list_outcome.IsSuccess())
    return (int)list_outcome.GetError().GetResponseCode();

  Aws::Vector<Aws::S3::Model::Bucket> bucket_list =
              list_outcome.GetResult().GetBuckets();
  *real_size = bucket_list.size();
  if (b_size < bucket_list.size())
  {
    return -ENOMEM;
  }
  int it = 0;
  for (auto const &bucket : bucket_list)
  {
    const Aws::String& bkt_name = bucket.GetName();
		buckets[it].name_len = bkt_name.length();
    do_out_buffer(bkt_name.c_str(), &(buckets[it].name), buckets[it].name_len);
    it++;
  }
  return 0;
}

extern "C" int Get_Bucket_Acl_Size(S3_Client s3_cli, const char* bucket_name, size_t* size)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::GetBucketAclRequest acl_req;
  acl_req.SetBucket(bucket_name);
	
  auto acl_outcome = s3_client->GetBucketAcl(acl_req);
  if (!acl_outcome.IsSuccess())
    return (int)acl_outcome.GetError().GetResponseCode();
	
  Aws::Vector<Aws::S3::Model::Grant> grants = acl_outcome.GetResult().GetGrants();
  *size = grants.size();

  return 0;
}

extern "C" int Get_Bucket_Acl(S3_Client s3_cli, const char *bucket_name, 
                                   acl_info_t *acls, const size_t len)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::GetBucketAclRequest acl_req;
  acl_req.SetBucket(bucket_name);
	
  auto acl_outcome = s3_client->GetBucketAcl(acl_req);
  if (!acl_outcome.IsSuccess())
    return (int)acl_outcome.GetError().GetResponseCode();
  int it = 0;
  Aws::Vector<Aws::S3::Model::Grant> grants = acl_outcome.GetResult().GetGrants();
  if (grants.size() > len)
    return -ENOMEM;
  for (auto const &grant : grants)
  {
    const Aws::String& tmp_acl = Aws::S3::Model::PermissionMapper::GetNameForPermission(
                                  grant.GetPermission());
    const Aws::String& tmp_user_id = grant.GetGrantee().GetID();

    acls[it].acl_len = tmp_acl.length();
    do_out_buffer(tmp_acl.c_str(), &(acls[it].acl), acls[it].acl_len);
    acls[it].user_id_len = tmp_user_id.length();
    do_out_buffer(tmp_user_id.c_str(), &(acls[it].user_id), acls[it].user_id_len);
    it++;
  }
  return 0;
}

extern "C" int Put_Bucket_Acl(S3_Client s3_cli, const char* bucket_name,
                                  const acl_info_t acl)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::PutBucketAclRequest acl_req;
  acl_req.SetBucket(bucket_name);
  acl_req.SetACL(Aws::S3::Model::BucketCannedACLMapper::GetBucketCannedACLForName(acl.acl));
  auto acl_outcome = s3_client->PutBucketAcl(acl_req);
  if (!acl_outcome.IsSuccess())
    return (int)acl_outcome.GetError().GetResponseCode();

  return 0;
}

/** object feature */
extern "C" int Create_Object(S3_Client s3_cli, const char* bucket_name, 
                 const char* object_name)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  
  Aws::S3::Model::PutObjectRequest object_request;
  object_request.WithBucket(bucket_name)
                .WithKey(object_name);
	
  auto create_outcome =s3_client->PutObject(object_request);
  if (!create_outcome.IsSuccess())
    return (int)create_outcome.GetError().GetResponseCode();
  return 0;
}

extern "C" int Put_Object(S3_Client s3_cli, const char* bucket_name, 
                 const char* object_name, const char* buf, size_t len, 
                 meta_info_t* meta, const size_t meta_size,
                 const char* acl)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::PutObjectRequest object_request;
  object_request.WithBucket(bucket_name)
                .WithKey(object_name);
	
  if (meta)
  {
    Aws::Map<Aws::String, Aws::String> c_meta;
    for (unsigned int it = 0; it < meta_size; it++)
    {
      c_meta[meta[it].key] = meta[it].val;
    }
    object_request.SetMetadata(c_meta);
  }
  if (acl)
  {
    Aws::S3::Model::ObjectCannedACL obj_acl = 
            Aws::S3::Model::ObjectCannedACLMapper::GetObjectCannedACLForName(acl);
    object_request.SetACL(obj_acl);
  }
  auto sstream = std::make_shared<std::stringstream>();
  sstream->write(buf, len);
  object_request.SetBody(sstream);
	
  auto put_object_outcome = s3_client->PutObject(object_request);

  if (!put_object_outcome.IsSuccess())
    return (int)put_object_outcome.GetError().GetResponseCode();

  return 0;
}

/*
extern "C" int Put_Object_File(S3_Client s3_cli, const char* bucket_name, 
                 const char* object_name, char* file,
                 meta_info_t* meta, const size_t meta_size,
                 const char* acl)
{
  return -EINVAL;
}
*/

extern "C" int Put_Object_Acl(S3_Client s3_cli, const char* bucket_name, 
                       const char* object_name, const char* acl)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::PutObjectAclRequest acl_req;
  acl_req.WithBucket(bucket_name).WithKey(object_name);
  Aws::S3::Model::ObjectCannedACL obj_acl = 
            Aws::S3::Model::ObjectCannedACLMapper::GetObjectCannedACLForName(acl);
  acl_req.SetACL(obj_acl);
	
  auto acl_outcome = s3_client->PutObjectAcl(acl_req);
  if (!acl_outcome.IsSuccess())
    return (int)acl_outcome.GetError().GetResponseCode();

  return 0;
}

extern "C" int Get_Object_Acl(S3_Client s3_cli, const char* bucket_name, 
                       const char* object_name, char** acl, size_t* len)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::GetObjectAclRequest acl_req;
  acl_req.WithBucket(bucket_name).WithKey(object_name);

  auto acl_outcome = s3_client->GetObjectAcl(acl_req);
  if (!acl_outcome.IsSuccess())
    return (int)acl_outcome.GetError().GetResponseCode();
	
  Aws::Vector<Aws::S3::Model::Grant> grants = acl_outcome.GetResult().GetGrants();
  int it = 0;
  for (auto const &grant : grants)
  {
    const Aws::String& tmp_acl = Aws::S3::Model::PermissionMapper::GetNameForPermission(
								grant.GetPermission());
    //const Aws::String& tmp_user_id = grant.GetGrantee().GetID();
    *len = tmp_acl.length();
    do_out_buffer(tmp_acl.c_str(), acl, *len);
    it++;
  }
	
  return 0;
}

/*
extern "C" int Get_Object_File(S3_Client s3_cli, const char* bucket_name, 
                 const char* object_name, const char* file_name,
                 char* version_id)
{

}
*/

extern "C" int Get_Object(S3_Client s3_cli, const char* bucket_name, 
                 const char* object_name, char* buf, size_t len,
                 int64_t off, int part_num, char* version_id)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::GetObjectRequest get_req;
  get_req.SetBucket(bucket_name);
  get_req.SetKey(object_name);
  if (version_id)
    get_req.SetVersionId(version_id);
  if (part_num != -1)
    get_req.SetPartNumber(part_num);
  if (off != -1)
  {
    //std::string s = boost::lexical_cast<string>(aa);
    std::stringstream ss;
    ss << "Range: bytes=" << off << "-" << off+len;
    get_req.SetRange(ss.str().c_str());
  }
		
  auto get_outcome = s3_client->GetObject(get_req);
  if (!get_outcome.IsSuccess())
    return -(int)get_outcome.GetError().GetResponseCode();

  if (NULL == buf)
    return -ENOMEM;
  get_outcome.GetResult().GetBody().clear();
  std::streambuf* out_stream = get_outcome.GetResult().GetBody().rdbuf();
  std::streamsize size = out_stream->sgetn(buf, len);
  return (int)size;


}

extern "C" int Put_Object_Metadata(S3_Client s3_cli, const char* bucket_name, 
                              const char* object_name, meta_info_t* meta, 
                              const size_t meta_size)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::PutObjectRequest get_req;
  get_req.SetBucket(bucket_name);
  get_req.SetKey(object_name);
  Aws::Map<Aws::String, Aws::String> a_meta;
  for (unsigned int it = 0; it < meta_size; it++)
  { 
    a_meta[meta[it].key] = meta[it].val;
  }
  get_req.SetMetadata(a_meta);
  auto meta_outcome = s3_client->PutObject(get_req);
  if (!meta_outcome.IsSuccess())
    return (int)meta_outcome.GetError().GetResponseCode();
  return 0;
}

extern "C" int Get_Object_Info(S3_Client s3_cli, const char * bucket_name,
                              const char * object_name, object_info_t* obj_info)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::HeadObjectRequest head_req;
  head_req.SetBucket(bucket_name);
  head_req.SetKey(object_name);
  memset(obj_info, 0, sizeof(object_info_t));
  auto head_outcome = s3_client->HeadObject(head_req);
  if (!head_outcome.IsSuccess())
    return (int)head_outcome.GetError().GetResponseCode();
  Aws::Map<Aws::String, Aws::String> meta_ = head_outcome.GetResult().GetMetadata();
  obj_info->meta_len = meta_.size();
  int mi = 0;
  if (obj_info->meta_len)
  {
    obj_info->object_meta = (meta_info_t *)malloc(sizeof(meta_info_t) * obj_info->meta_len);

    for (Aws::Map<Aws::String, Aws::String>::iterator it = meta_.begin();
         it != meta_.end();
         it++)
    {
      obj_info->object_meta[mi].key_len = it->first.length();
      do_out_buffer(it->first.c_str(), &(obj_info->object_meta[mi].key),
                   it->first.length());
      obj_info->object_meta[mi].val_len = it->second.length();
      do_out_buffer(it->second.c_str(), &(obj_info->object_meta[mi].val),
                   it->second.length());
      mi++;
    }
  }
  obj_info->mtime = head_outcome.GetResult().GetLastModified().Millis() / 1000;
  obj_info->size = head_outcome.GetResult().GetContentLength();
	//maybe have bug
  obj_info->name_len = strlen(object_name);
  do_out_buffer(object_name, &(obj_info->name), obj_info->name_len);
  if ('/' == object_name[strlen(object_name)-1])
    obj_info->st_mode = S_IFDIR;
  else
    obj_info->st_mode = S_IFREG;
  return 0;
}

extern "C" int List_Object(S3_Client s3_cli, const char *bucket_name,
                  object_info_t *obj_info, size_t *info_len,
                  const char *perfix, const char *delimiter,
                  char **marker, int get_meta, bool* istruncated)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::ListObjectsRequest list_req;
  int ret = 0;
  list_req.SetBucket(bucket_name);
  list_req.SetMaxKeys(*info_len);
  if (perfix)
    list_req.SetPrefix(perfix);
  if (delimiter)
    list_req.SetDelimiter(delimiter);
  if (*marker)
    list_req.SetMarker(*marker);
  memset(obj_info, 0, sizeof(object_info_t) * *info_len);
  auto list_outcome = s3_client->ListObjects(list_req);
    
  if (!list_outcome.IsSuccess())
    return (int)list_outcome.GetError().GetResponseCode();

  Aws::Vector<Aws::S3::Model::Object> object_list = list_outcome.GetResult().GetContents();
  if (list_outcome.GetResult().GetIsTruncated())
  {
    const Aws::String& next_marker = list_outcome.GetResult().GetNextMarker();
    do_out_buffer(next_marker.c_str(), marker, next_marker.length());
    *istruncated = true;
  }
    
  int it = 0;
  for (auto const &object : object_list)
  {
    Aws::String object_name = Aws::Utils::Xml::DecodeEscapedXmlText(object.GetKey());
    if (get_meta)
    {
      ret = Get_Object_Info(s3_cli, bucket_name, object_name.c_str(), &obj_info[it]);
      if (ret)
        continue;
    }
    else
    {
      obj_info[it].name_len = object_name.length();
      do_out_buffer(object_name.c_str(), &(obj_info[it].name), obj_info[it].name_len);
    }
    it++;
  }
  Aws::Vector<Aws::S3::Model::CommonPrefix> dir_list = list_outcome.GetResult().GetCommonPrefixes();
  for (auto const &dir : dir_list)
  {
    Aws::String dir_name = Aws::Utils::Xml::DecodeEscapedXmlText(dir.GetPrefix());
    ret = Get_Object_Info(s3_cli, bucket_name, dir_name.c_str(), &obj_info[it]);
    if (ret)
    {
      obj_info[it].name_len = dir_name.size();
      do_out_buffer(dir_name.c_str(), &obj_info[it].name, obj_info[it].name_len);
      obj_info[it].st_mode = S_IFDIR;
    }
    it++;
  }
  *info_len = it;
  return 0;
}


extern "C" int Init_Multipart_Upload(S3_Client s3_cli, const char *bucket_name,
                              const char *object_name, char **upload_id,
                              com_multipart_t *com, meta_info_t* meta,
                              const size_t meta_size, const char* acl)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::CreateMultipartUploadRequest cre_upload_req;
  cre_upload_req.SetBucket(bucket_name);
  cre_upload_req.SetKey(object_name);
  if (meta)
  {
    Aws::Map<Aws::String, Aws::String> c_meta;
    for (unsigned int it = 0; it < meta_size; it++)
      c_meta[meta[it].key] = meta[it].val;
    
    cre_upload_req.SetMetadata(c_meta);
  }
  if (acl)
  {
    Aws::S3::Model::ObjectCannedACL obj_acl = 
            Aws::S3::Model::ObjectCannedACLMapper::GetObjectCannedACLForName(acl);
    cre_upload_req.SetACL(obj_acl);
  }
 
  auto create_outcome = s3_client->CreateMultipartUpload(cre_upload_req);
  if (!create_outcome.IsSuccess())
    return (int)create_outcome.GetError().GetResponseCode();

  const Aws::String& c_upload_id = create_outcome.GetResult().GetUploadId();
  do_out_buffer(c_upload_id.c_str(), upload_id, c_upload_id.length());
	
  Aws::S3::Model::CompletedMultipartUpload *com_upload = 
                 new Aws::S3::Model::CompletedMultipartUpload();
  *com = reinterpret_cast<com_multipart_t>(com_upload);

  return 0;
}

extern "C" int Upload_Part(S3_Client s3_cli, com_multipart_t com, const char *bucket_name, 
                   const char *object_name, const char *upload_id, int part_id, 
                   const char *buf,  size_t len)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::CompletedMultipartUpload *com_upload = 
                              (Aws::S3::Model::CompletedMultipartUpload *)com;
  Aws::S3::Model::UploadPartRequest upload_req;
  upload_req.WithBucket(bucket_name)
            .WithKey(object_name)
            .WithPartNumber(part_id + 1)
            .WithContentLength(len)
            .WithUploadId(upload_id);

  auto sstream = std::make_shared<std::stringstream>();
  sstream->write(buf, len);
  upload_req.SetBody(sstream);
  auto upload_outcome = s3_client->UploadPart(upload_req);
  if (!upload_outcome.IsSuccess())
    return (int)upload_outcome.GetError().GetResponseCode();

  Aws::S3::Model::CompletedPart part;
  part.SetPartNumber(upload_req.GetPartNumber());
  part.SetETag(upload_outcome.GetResult().GetETag());
  com_upload->AddParts(part);
	
  return 0;
}

extern "C" int Complete_Multipart_Upload(S3_Client s3_cli, com_multipart_t com, 
                                     const char *bucket_name, const char *object_name, 
                                     const char *upload_id)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::CompletedMultipartUpload *com_upload = 
                              (Aws::S3::Model::CompletedMultipartUpload *)com;  
  Aws::S3::Model::CompleteMultipartUploadRequest com_req;
  com_req.WithBucket(bucket_name)
         .WithKey(object_name)
         .WithUploadId(upload_id)
         .WithMultipartUpload(*com_upload);
			
  auto comp_outcome = s3_client->CompleteMultipartUpload(com_req);
  if (!comp_outcome.IsSuccess())
    return (int)comp_outcome.GetError().GetResponseCode();
  return 0;
}

extern "C" void Destroy_Upload(com_multipart_t com)
{
  Aws::S3::Model::CompletedMultipartUpload *com_upload = 
               (Aws::S3::Model::CompletedMultipartUpload *)com;
  if (com_upload)
    delete com_upload;
  com_upload = NULL;
}

extern "C" int Abort_Multipart_Upload(S3_Client s3_cli, const char *bucket_name, 
                                 const char *object_name, const char *upload_id)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::AbortMultipartUploadRequest abort_req;
  abort_req.WithBucket(bucket_name)
           .WithKey(object_name)
           .WithUploadId(upload_id);
  auto abort_outcome = s3_client->AbortMultipartUpload(abort_req);
  if (!abort_outcome.IsSuccess())
    return (int)abort_outcome.GetError().GetResponseCode();
  return 0;
}

extern "C" int Delete_Object(S3_Client s3_cli, const char *bucket_name, 
                     const char *object_name)
{
  Aws::S3::S3Client *s3_client = (Aws::S3::S3Client *)s3_cli;
  Aws::S3::Model::DeleteObjectRequest del_req;
  del_req.WithBucket(bucket_name)
         .WithKey(object_name);
  auto del_outcome = s3_client->DeleteObject(del_req);
  if (!del_outcome.IsSuccess())
    return (int)del_outcome.GetError().GetResponseCode();
  return 0;
}





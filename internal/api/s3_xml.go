package api

import (
	"encoding/xml"
	"time"

	"my-s3/internal/storage"
)

// S3 XML Namespaces
const S3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/"

// Owner represents bucket/object owner
type Owner struct {
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// BucketXML represents a bucket in S3 XML format
type BucketXML struct {
	Name         string `xml:"Name"`
	CreationDate string `xml:"CreationDate"`
}

// BucketsList holds bucket list
type BucketsList struct {
	Bucket []BucketXML `xml:"Bucket"`
}

// ListAllMyBucketsResult represents S3 ListBuckets response
type ListAllMyBucketsResult struct {
	XMLName xml.Name    `xml:"ListAllMyBucketsResult"`
	Xmlns   string      `xml:"xmlns,attr"`
	Owner   Owner       `xml:"Owner"`
	Buckets BucketsList `xml:"Buckets"`
}

// ObjectXML represents object in ListObjects response
type ObjectXML struct {
	Key          string `xml:"Key"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
	Owner        Owner  `xml:"Owner"`
}

// CommonPrefixXML represents delimiter prefixes
type CommonPrefixXML struct {
	Prefix string `xml:"Prefix"`
}

// ListBucketResult represents S3 ListObjects (v1 and v2) response
type ListBucketResult struct {
	XMLName               xml.Name          `xml:"ListBucketResult"`
	Xmlns                 string            `xml:"xmlns,attr"`
	Name                  string            `xml:"Name"`
	Prefix                string            `xml:"Prefix"`
	Marker                string            `xml:"Marker,omitempty"`
	NextMarker            string            `xml:"NextMarker,omitempty"`
	ContinuationToken     string            `xml:"ContinuationToken,omitempty"`
	NextContinuationToken string            `xml:"NextContinuationToken,omitempty"`
	KeyCount              int               `xml:"KeyCount"`
	MaxKeys               int               `xml:"MaxKeys"`
	Delimiter             string            `xml:"Delimiter,omitempty"`
	IsTruncated           bool              `xml:"IsTruncated"`
	Contents              []ObjectXML       `xml:"Contents"`
	CommonPrefixes        []CommonPrefixXML `xml:"CommonPrefixes,omitempty"`
}

// ErrorResponse represents AWS standard S3 XML error
type ErrorResponse struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	Resource  string   `xml:"Resource,omitempty"`
	RequestId string   `xml:"RequestId"`
	HostId    string   `xml:"HostId,omitempty"`
}

// FormatTime formats timestamp for S3 XML
func FormatTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}


// InitiateMultipartUploadResult XML format
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadId string   `xml:"UploadId"`
}

// CompleteMultipartUploadRequest XML from client
type CompleteMultipartUploadRequest struct {
	XMLName xml.Name               `xml:"CompleteMultipartUpload"`
	Part    []storage.CompletePart `xml:"Part"`
}

// CompleteMultipartUploadResult XML sent to client
type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Xmlns    string   `xml:"xmlns,attr"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// PartXML describes a part inside ListPartsResult
type PartXML struct {
	PartNumber   int    `xml:"PartNumber"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
}

// ListPartsResult represents GET /{bucket}/{key}?uploadId=... response
type ListPartsResult struct {
	XMLName      xml.Name  `xml:"ListPartsResult"`
	Xmlns        string    `xml:"xmlns,attr"`
	Bucket       string    `xml:"Bucket"`
	Key          string    `xml:"Key"`
	UploadId     string    `xml:"UploadId"`
	StorageClass string    `xml:"StorageClass"`
	MaxParts     int       `xml:"MaxParts"`
	IsTruncated  bool      `xml:"IsTruncated"`
	Part         []PartXML `xml:"Part,omitempty"`
}

// UploadXML represents an active upload inside ListMultipartUploadsResult
type UploadXML struct {
	Key          string `xml:"Key"`
	UploadId     string `xml:"UploadId"`
	StorageClass string `xml:"StorageClass"`
	Initiated    string `xml:"Initiated"`
}

// ListMultipartUploadsResult represents GET /{bucket}?uploads response
type ListMultipartUploadsResult struct {
	XMLName     xml.Name    `xml:"ListMultipartUploadsResult"`
	Xmlns       string      `xml:"xmlns,attr"`
	Bucket      string      `xml:"Bucket"`
	MaxUploads  int         `xml:"MaxUploads"`
	IsTruncated bool        `xml:"IsTruncated"`
	Upload      []UploadXML `xml:"Upload,omitempty"`
}

// DeleteObjectIdentifierXML represents a key inside POST /{bucket}?delete XML
type DeleteObjectIdentifierXML struct {
	Key string `xml:"Key"`
}

// DeleteObjectsRequest represents AWS S3 multi-object batch delete XML
type DeleteObjectsRequest struct {
	XMLName xml.Name                    `xml:"Delete"`
	Quiet   bool                        `xml:"Quiet,omitempty"`
	Object  []DeleteObjectIdentifierXML `xml:"Object"`
}

// DeletedObjectXML represents a successfully deleted object
type DeletedObjectXML struct {
	Key string `xml:"Key"`
}

// DeleteErrorXML represents a failed item in batch delete
type DeleteErrorXML struct {
	Key     string `xml:"Key"`
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

// DeleteResult represents POST /{bucket}?delete XML response
type DeleteResult struct {
	XMLName xml.Name           `xml:"DeleteResult"`
	Xmlns   string             `xml:"xmlns,attr"`
	Deleted []DeletedObjectXML `xml:"Deleted,omitempty"`
	Error   []DeleteErrorXML   `xml:"Error,omitempty"`
}

// CopyObjectResult represents PUT object with x-amz-copy-source response
type CopyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	Xmlns        string   `xml:"xmlns,attr"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// CopyPartResult represents UploadPartCopy XML response
type CopyPartResult struct {
	XMLName      xml.Name `xml:"CopyPartResult"`
	Xmlns        string   `xml:"xmlns,attr"`
	LastModified string   `xml:"LastModified"`
	ETag         string   `xml:"ETag"`
}

// LocationConstraintResult represents GET /{bucket}?location XML
type LocationConstraintResult struct {
	XMLName  xml.Name `xml:"LocationConstraint"`
	Xmlns    string   `xml:"xmlns,attr"`
	Location string   `xml:",chardata"`
}

// VersioningConfiguration represents GET /{bucket}?versioning XML
type VersioningConfiguration struct {
	XMLName xml.Name `xml:"VersioningConfiguration"`
	Xmlns   string   `xml:"xmlns,attr"`
	Status  string   `xml:"Status,omitempty"`
}

// GranteeXML represents ACL grantee
type GranteeXML struct {
	Xmlns       string `xml:"xmlns:xsi,attr"`
	Type        string `xml:"xsi:type,attr"`
	ID          string `xml:"ID"`
	DisplayName string `xml:"DisplayName"`
}

// GrantXML represents ACL grant entry
type GrantXML struct {
	Grantee    GranteeXML `xml:"Grantee"`
	Permission string     `xml:"Permission"`
}

// AccessControlPolicy represents GET ?acl XML
type AccessControlPolicy struct {
	XMLName           xml.Name   `xml:"AccessControlPolicy"`
	Xmlns             string     `xml:"xmlns,attr"`
	Owner             Owner      `xml:"Owner"`
	AccessControlList []GrantXML `xml:"AccessControlList>Grant"`
}

// TagXML represents a key-value tag
type TagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

// TagSetXML wraps tags
type TagSetXML struct {
	Tag []TagXML `xml:"Tag,omitempty"`
}

// TaggingXML represents S3 GET/PUT ?tagging XML
type TaggingXML struct {
	XMLName xml.Name  `xml:"Tagging"`
	Xmlns   string    `xml:"xmlns,attr,omitempty"`
	TagSet  TagSetXML `xml:"TagSet"`
}

// VersionXML describes a non-delete-marker object version
type VersionXML struct {
	Key          string `xml:"Key"`
	VersionId    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	ETag         string `xml:"ETag"`
	Size         int64  `xml:"Size"`
	StorageClass string `xml:"StorageClass"`
	Owner        Owner  `xml:"Owner"`
}

// DeleteMarkerXML describes a delete marker in ListVersionsResult
type DeleteMarkerXML struct {
	Key          string `xml:"Key"`
	VersionId    string `xml:"VersionId"`
	IsLatest     bool   `xml:"IsLatest"`
	LastModified string `xml:"LastModified"`
	Owner        Owner  `xml:"Owner"`
}

// ListVersionsResult represents GET /{bucket}?versions XML
type ListVersionsResult struct {
	XMLName      xml.Name          `xml:"ListVersionsResult"`
	Xmlns        string            `xml:"xmlns,attr"`
	Name         string            `xml:"Name"`
	Prefix       string            `xml:"Prefix"`
	MaxKeys      int               `xml:"MaxKeys"`
	IsTruncated  bool              `xml:"IsTruncated"`
	Version      []VersionXML      `xml:"Version,omitempty"`
	DeleteMarker []DeleteMarkerXML `xml:"DeleteMarker,omitempty"`
}

// ObjectLockConfigurationXML represents ?object-lock config
type ObjectLockConfigurationXML struct {
	XMLName           xml.Name `xml:"ObjectLockConfiguration"`
	Xmlns             string   `xml:"xmlns,attr,omitempty"`
	ObjectLockEnabled string   `xml:"ObjectLockEnabled"`
}

// ObjectRetentionXML represents GET/PUT ?retention
type ObjectRetentionXML struct {
	XMLName         xml.Name `xml:"Retention"`
	Xmlns           string   `xml:"xmlns,attr,omitempty"`
	Mode            string   `xml:"Mode"`
	RetainUntilDate string   `xml:"RetainUntilDate"`
}

// ObjectLegalHoldXML represents GET/PUT ?legal-hold
type ObjectLegalHoldXML struct {
	XMLName xml.Name `xml:"LegalHold"`
	Xmlns   string   `xml:"xmlns,attr,omitempty"`
	Status  string   `xml:"Status"`
}

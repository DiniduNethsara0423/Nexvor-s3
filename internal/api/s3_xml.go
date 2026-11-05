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

#ifndef __CHECKSUM__
#define __CHECKSUM__

control ComputeChecksumImpl(inout parsed_headers_t hdr,
                            inout local_metadata_t meta)
{
    apply {}
}

control VerifyChecksumImpl(inout parsed_headers_t hdr,
                           inout local_metadata_t meta)
{
    apply {}
}

#endif

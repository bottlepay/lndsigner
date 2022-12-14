// Copyright (C) 2013-2017 The btcsuite developers
// Copyright (C) 2015-2016 The Decred developers
// Copyright (C) 2015-2022 Lightning Labs and The Lightning Network Developers
// Copyright (C) 2022 Bottlepay and The Lightning Network Developers

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0-devel
// 	protoc        v3.14.0
// source: walletkit.proto

package proto

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type SignPsbtRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	//
	//The PSBT that should be signed. The PSBT must contain all required inputs,
	//outputs, UTXO data and custom fields required to identify the signing key.
	FundedPsbt []byte `protobuf:"bytes,1,opt,name=funded_psbt,json=fundedPsbt,proto3" json:"funded_psbt,omitempty"`
}

func (x *SignPsbtRequest) Reset() {
	*x = SignPsbtRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_walletkit_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignPsbtRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignPsbtRequest) ProtoMessage() {}

func (x *SignPsbtRequest) ProtoReflect() protoreflect.Message {
	mi := &file_walletkit_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignPsbtRequest.ProtoReflect.Descriptor instead.
func (*SignPsbtRequest) Descriptor() ([]byte, []int) {
	return file_walletkit_proto_rawDescGZIP(), []int{0}
}

func (x *SignPsbtRequest) GetFundedPsbt() []byte {
	if x != nil {
		return x.FundedPsbt
	}
	return nil
}

type SignPsbtResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The signed transaction in PSBT format.
	SignedPsbt []byte `protobuf:"bytes,1,opt,name=signed_psbt,json=signedPsbt,proto3" json:"signed_psbt,omitempty"`
	// The indices of signed inputs.
	SignedInputs []uint32 `protobuf:"varint,2,rep,packed,name=signed_inputs,json=signedInputs,proto3" json:"signed_inputs,omitempty"`
}

func (x *SignPsbtResponse) Reset() {
	*x = SignPsbtResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_walletkit_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SignPsbtResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SignPsbtResponse) ProtoMessage() {}

func (x *SignPsbtResponse) ProtoReflect() protoreflect.Message {
	mi := &file_walletkit_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SignPsbtResponse.ProtoReflect.Descriptor instead.
func (*SignPsbtResponse) Descriptor() ([]byte, []int) {
	return file_walletkit_proto_rawDescGZIP(), []int{1}
}

func (x *SignPsbtResponse) GetSignedPsbt() []byte {
	if x != nil {
		return x.SignedPsbt
	}
	return nil
}

func (x *SignPsbtResponse) GetSignedInputs() []uint32 {
	if x != nil {
		return x.SignedInputs
	}
	return nil
}

var File_walletkit_proto protoreflect.FileDescriptor

var file_walletkit_proto_rawDesc = []byte{
	0x0a, 0x0f, 0x77, 0x61, 0x6c, 0x6c, 0x65, 0x74, 0x6b, 0x69, 0x74, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x32, 0x0a, 0x0f, 0x53, 0x69, 0x67, 0x6e,
	0x50, 0x73, 0x62, 0x74, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x1f, 0x0a, 0x0b, 0x66,
	0x75, 0x6e, 0x64, 0x65, 0x64, 0x5f, 0x70, 0x73, 0x62, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x0a, 0x66, 0x75, 0x6e, 0x64, 0x65, 0x64, 0x50, 0x73, 0x62, 0x74, 0x22, 0x58, 0x0a, 0x10,
	0x53, 0x69, 0x67, 0x6e, 0x50, 0x73, 0x62, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x1f, 0x0a, 0x0b, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x70, 0x73, 0x62, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x50, 0x73, 0x62,
	0x74, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x70, 0x75,
	0x74, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0d, 0x52, 0x0c, 0x73, 0x69, 0x67, 0x6e, 0x65, 0x64,
	0x49, 0x6e, 0x70, 0x75, 0x74, 0x73, 0x32, 0x48, 0x0a, 0x09, 0x57, 0x61, 0x6c, 0x6c, 0x65, 0x74,
	0x4b, 0x69, 0x74, 0x12, 0x3b, 0x0a, 0x08, 0x53, 0x69, 0x67, 0x6e, 0x50, 0x73, 0x62, 0x74, 0x12,
	0x16, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x69, 0x67, 0x6e, 0x50, 0x73, 0x62, 0x74,
	0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x17, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x53, 0x69, 0x67, 0x6e, 0x50, 0x73, 0x62, 0x74, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x42, 0x26, 0x5a, 0x24, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x62,
	0x6f, 0x74, 0x74, 0x6c, 0x65, 0x70, 0x61, 0x79, 0x2f, 0x6c, 0x6e, 0x64, 0x73, 0x69, 0x67, 0x6e,
	0x65, 0x72, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_walletkit_proto_rawDescOnce sync.Once
	file_walletkit_proto_rawDescData = file_walletkit_proto_rawDesc
)

func file_walletkit_proto_rawDescGZIP() []byte {
	file_walletkit_proto_rawDescOnce.Do(func() {
		file_walletkit_proto_rawDescData = protoimpl.X.CompressGZIP(file_walletkit_proto_rawDescData)
	})
	return file_walletkit_proto_rawDescData
}

var file_walletkit_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_walletkit_proto_goTypes = []interface{}{
	(*SignPsbtRequest)(nil),  // 0: proto.SignPsbtRequest
	(*SignPsbtResponse)(nil), // 1: proto.SignPsbtResponse
}
var file_walletkit_proto_depIdxs = []int32{
	0, // 0: proto.WalletKit.SignPsbt:input_type -> proto.SignPsbtRequest
	1, // 1: proto.WalletKit.SignPsbt:output_type -> proto.SignPsbtResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_walletkit_proto_init() }
func file_walletkit_proto_init() {
	if File_walletkit_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_walletkit_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignPsbtRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_walletkit_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SignPsbtResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_walletkit_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_walletkit_proto_goTypes,
		DependencyIndexes: file_walletkit_proto_depIdxs,
		MessageInfos:      file_walletkit_proto_msgTypes,
	}.Build()
	File_walletkit_proto = out.File
	file_walletkit_proto_rawDesc = nil
	file_walletkit_proto_goTypes = nil
	file_walletkit_proto_depIdxs = nil
}

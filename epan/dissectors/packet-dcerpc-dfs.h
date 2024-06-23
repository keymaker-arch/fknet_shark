/* DO NOT EDIT
	This file was automatically generated by Pidl
	from dfs.idl and dfs.cnf.

	Pidl is a perl based IDL compiler for DCE/RPC idl files.
	It is maintained by the Samba team, not the Wireshark team.
	Instructions on how to download and install Pidl can be
	found at https://gitlab.com/wireshark/wireshark/-/wikis/Pidl
*/

#ifndef __PACKET_DCERPC_NETDFS_H
#define __PACKET_DCERPC_NETDFS_H

#define DFS_STORAGE_STATES	( 0xf )

#define DFS_MANAGER_VERSION_NT4 (1)
#define DFS_MANAGER_VERSION_W2K (2)
#define DFS_MANAGER_VERSION_W2K3 (4)
extern const value_string netdfs_dfs_ManagerVersion_vals[];
int netdfs_dissect_enum_dfs_ManagerVersion(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, guint32 *param _U_);
int netdfs_dissect_struct_dfs_Info0(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_bitmap_dfs_VolumeState(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_bitmap_dfs_StorageState(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_StorageInfo(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_bitmap_dfs_PropertyFlags(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info5(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
#define DFS_INVALID_PRIORITY_CLASS (-1)
#define DFS_SITE_COST_NORMAL_PRIORITY_CLASS (0)
#define DFS_GLOBAL_HIGH_PRIORITY_CLASS (1)
#define DFS_SITE_COST_HIGH_PRIORITY_CLASS (2)
#define DFS_SITE_COST_LOW_PRIORITY_CLASS (3)
#define DFS_GLOBAL_LOW_PRIORITY_CLASS (4)
extern const value_string netdfs_dfs_Target_PriorityClass_vals[];
int netdfs_dissect_enum_dfs_Target_PriorityClass(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, guint32 *param _U_);
int netdfs_dissect_struct_dfs_Target_Priority(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_StorageInfo2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info6(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info7(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info100(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info101(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info102(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info103(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info104(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info105(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info106(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_Info200(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
#define DFS_VOLUME_FLAVOR_STANDALONE (0x100)
#define DFS_VOLUME_FLAVOR_AD_BLOB (0x200)
extern const value_string netdfs_dfs_VolumeFlavor_vals[];
int netdfs_dissect_enum_dfs_VolumeFlavor(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, guint1632 *param _U_);
int netdfs_dissect_struct_dfs_Info300(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_EnumArray1(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_EnumArray2(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_EnumArray3(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_EnumArray4(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_EnumArray200(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_EnumArray300(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_EnumStruct(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
int netdfs_dissect_struct_dfs_UnknownStruct(tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_, dcerpc_info* di _U_, uint8_t *drep _U_, int hf_index _U_, uint32_t param _U_);
#endif /* __PACKET_DCERPC_NETDFS_H */

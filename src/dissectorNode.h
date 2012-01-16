
#ifndef _node_h_
#define _node_h_

#include <v8.h>
#include <node.h>
#include <config.h>
#include <epan/epan.h>

class DissectorNode : node::ObjectWrap {
public:
  static void Init(v8::Handle<v8::Object> target);
  static v8::Local<v8::Object> New(frame_data *fdata, epan_dissect_t *edt, proto_node *node, v8::Handle<v8::Value> parent);
  bool isRoot() { return m_parent.IsEmpty() || m_parent->IsNull(); }
  
private:
  DissectorNode(frame_data *fdata, epan_dissect_t *edt, proto_node *node, v8::Handle<v8::Value> parent);
  ~DissectorNode();
  
  static void NotImplementedSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> AbbreviationGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info);
  static int getPositionInPacket(proto_node *node, field_info *fi);
  static const char* fixEscapes(const char* src, char* dest);
  static v8::Handle<v8::Value> representationGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info);
  static void representationSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info);
  static v8::Handle<v8::Value> valueGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info);
  static void valueSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info);
  void createChildren();
  static void createChildrenItem(proto_node *node, gpointer data);
  static v8::Handle<v8::Value> childGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info);
  static void childSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info);
  
  static v8::Persistent<v8::FunctionTemplate> s_ct;
  v8::Handle<v8::Value> m_parent;
  frame_data *m_fdata;
  epan_dissect_t *m_edt;
  proto_node *m_node;
  v8::Persistent<v8::Value> m_representation;
  v8::Persistent<v8::Value> m_value;
  v8::Persistent<v8::Object> m_childStorage;
};

#endif

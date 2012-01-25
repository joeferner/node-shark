
#ifndef _lazydissectornode_h_
#define _lazydissectornode_h_

#include <v8.h>
#include <node.h>
extern "C" {
  #include <config.h>
  #include <epan/epan.h>
}

class LazyDissectorNode : node::ObjectWrap {
public:
  static void Init(v8::Handle<v8::Object> target);
  static v8::Local<v8::Object> New(frame_data *fdata, epan_dissect_t *edt, proto_node *node);
  proto_node* getProtoNode() { return m_node; }

private:
  LazyDissectorNode(frame_data *fdata, epan_dissect_t *edt, proto_node *node);
  ~LazyDissectorNode();

  static v8::Persistent<v8::FunctionTemplate> s_ct;
  frame_data *m_fdata;
  epan_dissect_t *m_edt;
  proto_node *m_node;
};

#endif

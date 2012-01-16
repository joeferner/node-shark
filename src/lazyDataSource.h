
#ifndef _lazydatasource_h_
#define _lazydatasource_h_

#include <v8.h>
#include <node.h>
#include <config.h>
#include <epan/epan.h>
#include <node_buffer.h>

class DissectorNode;

class LazyDataSource : node::ObjectWrap {
public:
  static void Init(v8::Handle<v8::Object> target);
  static v8::Local<v8::Object> New(DissectorNode *parent, tvbuff_t *tvb);
  node::Buffer* createBuffer();
  DissectorNode* getParent() { return m_parent; }  
  
private:
  LazyDataSource(DissectorNode *parent, tvbuff_t *tvb);
  ~LazyDataSource();
  
  static v8::Persistent<v8::FunctionTemplate> s_ct;
  DissectorNode *m_parent;
  tvbuff_t *m_tvb;
};

#endif


#include <string.h>
#include "lazyDataSource.h"

/*static*/ v8::Persistent<v8::FunctionTemplate> LazyDataSource::s_ct;

/*static*/ void LazyDataSource::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New();
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  s_ct->SetClassName(v8::String::NewSymbol("LazyDataSource"));

  target->Set(v8::String::NewSymbol("LazyDataSource"), s_ct->GetFunction());
}

/*static*/ v8::Local<v8::Object> LazyDataSource::New(DissectorNode *parent, tvbuff_t *tvb) {
  v8::HandleScope scope;
  v8::Local<v8::Function> ctor = s_ct->GetFunction();
  v8::Local<v8::Object> obj = ctor->NewInstance();
  LazyDataSource *self = new LazyDataSource(parent, tvb);
  self->Wrap(obj);
  
  return scope.Close(obj);
}

LazyDataSource::LazyDataSource(DissectorNode *parent, tvbuff_t *tvb) {
  m_parent = parent;
  m_tvb = tvb;
}

LazyDataSource::~LazyDataSource() {
  
}

node::Buffer* LazyDataSource::createBuffer() {
  guint length = tvb_length(m_tvb);
  const guchar *cp = tvb_get_ptr(m_tvb, 0, length);
  node::Buffer *buf = node::Buffer::New(length);
  memcpy(node::Buffer::Data(buf), cp, length);
  return buf;
}


#include "dissectorNode.h"
#include <epan/epan.h>
#include <wsutil/privileges.h>
#include <epan/epan_dissect.h>
#include <epan/to_str.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/packet.h>
#include <epan/plugins.h>
#include <node_buffer.h>
#include "utils.h"
#include "lazyDissectorNode.h"
#include "lazyDataSource.h"

/*static*/ v8::Persistent<v8::FunctionTemplate> DissectorNode::s_ct;

/*static*/ void DissectorNode::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New();
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  s_ct->SetClassName(v8::String::NewSymbol("Node"));

  target->Set(v8::String::NewSymbol("Node"), s_ct->GetFunction());
}

int DissectorNode::getPositionInPacket(proto_node *node, field_info *fi) {
  int posInPacket;
  if (node->parent && node->parent->finfo && (fi->start < node->parent->finfo->start)) {
    posInPacket = node->parent->finfo->start + fi->start;
  } else {
    posInPacket = fi->start;
  }
  return posInPacket;
}

const char* DissectorNode::fixEscapes(const char* src, char* dest) {
	const char* read = src;
	char* write = dest;
	while(*read) {
		if(*read == '\\') {
			read++;
			switch(*read) {
        case '\0': goto endOfRead;
        case '\\': *write++ = '\\'; read++; break;
				case 't': *write++ = '\t'; read++; break;
				case 'r': *write++ = '\r'; read++; break;
				case 'n': *write++ = '\n'; read++; break;
				default:
					*write++ = '\\';
					*write++ = *read++;
					break;
			}
		} else {
			*write++ = *read++;
		}
	}
endOfRead:
	*write++ = '\0';
	return dest;
}

v8::Handle<v8::Value> DissectorNode::getDataSourceName(tvbuff_t *tvb) {
	v8::HandleScope scope;
	for (GSList *src_le = m_edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
		data_source *src = (data_source*)src_le->data;
		if(tvb == src->tvb) {
			char *name = strdup(get_data_source_name(src));
			char *paren = strchr(name, '(');
			if(paren) *paren = '\0';
			strtrim(name);
			v8::Local<v8::String> result = v8::String::New(name);
			delete[] name;
			return scope.Close(result);
		}
	}
	return v8::Undefined();
}

/*static*/ v8::Local<v8::Object> DissectorNode::New(DissectorNode *root, frame_data *fdata, epan_dissect_t *edt, proto_node *node) {
	v8::HandleScope scope;
  v8::Local<v8::Function> ctor = s_ct->GetFunction();
  v8::Local<v8::Object> obj = ctor->NewInstance();
  DissectorNode *self = new DissectorNode(root, fdata, edt, node);
	self->Wrap(obj);	
	
  if(self->isRoot()) {
    obj->Set(v8::String::New("root"), v8::Boolean::New(true));
		
		v8::Local<v8::Object> dataSources = v8::Object::New();
		for (GSList *src_le = edt->pi.data_src; src_le != NULL; src_le = src_le->next) {
			data_source *src = (data_source*)src_le->data;
			tvbuff_t *tvb = src->tvb;
			v8::Local<v8::Object> lazyDataSource = LazyDataSource::New(self, tvb);
			dataSources->SetAccessor(self->getDataSourceName(src->tvb)->ToString(), dataSourceGetter, dataSourceSetter, lazyDataSource);
		}
		obj->Set(v8::String::New("dataSources"), dataSources);
  }

  field_info *fi = PNODE_FINFO(node);
  if(fi) {
    obj->Set(v8::String::New("sizeInPacket"), v8::Integer::New(fi->length));
    obj->Set(v8::String::New("positionInPacket"), v8::Integer::New(getPositionInPacket(node, fi)));
    obj->Set(v8::String::New("abbreviation"), v8::String::New(fi->hfinfo->abbrev));
		obj->Set(v8::String::New("dataSource"), self->getDataSourceName(fi->ds_tvb));
		
    if (fi->rep) {
			obj->SetAccessor(v8::String::New("representation"), representationGetter, representationSetter);
		}

		obj->SetAccessor(v8::String::New("value"), valueGetter, valueSetter);
  }
	
	self->createChildren();
	
  return scope.Close(obj);
}

void DissectorNode::createChildren() {
	proto_tree_children_foreach(m_node, createChildrenItem, this);
}

/*static*/ void DissectorNode::createChildrenItem(proto_node *node, gpointer data) {
	DissectorNode *self = (DissectorNode*)data;
	
	field_info *fi = PNODE_FINFO(node);
	if(fi) {
		const char *abbr = fi->hfinfo->abbrev;
		if(!self->isRoot()) {
			v8::String::AsciiValue parentAbbr(self->handle_->Get(v8::String::New("abbreviation")));
			int parentAbbrLen = strlen(*parentAbbr);
			if(strncmp(abbr, *parentAbbr, parentAbbrLen) == 0
				 && abbr[parentAbbrLen] == '.') {
				abbr += parentAbbrLen + 1;
			}
		}
		
		v8::Local<v8::Object> lazyNode = LazyDissectorNode::New(self->m_fdata, self->m_edt, node);
		self->handle_->SetAccessor(v8::String::New(abbr), childGetter, childSetter, lazyNode);
	}
}

/*static*/ v8::Handle<v8::Value> DissectorNode::childGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
	v8::HandleScope scope;
	DissectorNode *self = node::ObjectWrap::Unwrap<DissectorNode>(info.This());
	if(self->m_childStorage->Has(property)) {
		return scope.Close(self->m_childStorage->Get(property));
	} else {
		//v8::String::AsciiValue propertyStr(property);
		//printf("***** create child: %s\n", *propertyStr);
		
		LazyDissectorNode *lazyNode = node::ObjectWrap::Unwrap<LazyDissectorNode>(info.Data()->ToObject());
		v8::Local<v8::Object> newNodeObj = New(self->m_root, self->m_fdata, self->m_edt, lazyNode->getProtoNode());
		self->m_childStorage->Set(property, newNodeObj);
		return scope.Close(newNodeObj);
	}
}

/*static*/ void DissectorNode::childSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {
	v8::HandleScope scope;
	DissectorNode *self = node::ObjectWrap::Unwrap<DissectorNode>(info.This());
	self->m_childStorage->Set(property, value);
}

/*static*/ v8::Handle<v8::Value> DissectorNode::dataSourceGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
	v8::HandleScope scope;
	LazyDataSource *lazyDataSource = node::ObjectWrap::Unwrap<LazyDataSource>(info.Data()->ToObject());
	DissectorNode *self = lazyDataSource->getParent();
	if(self->m_dataSourceStorage->Has(property)) {
		return scope.Close(self->m_dataSourceStorage->Get(property));
	} else {
		//v8::String::AsciiValue propertyStr(property);
		//printf("***** create datasource: %s\n", *propertyStr);
		
		node::Buffer *buf = lazyDataSource->createBuffer();
		self->m_dataSourceStorage->Set(property, buf->handle_);
		return scope.Close(buf->handle_);
	}
}

/*static*/ void DissectorNode::dataSourceSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {
	v8::HandleScope scope;
	DissectorNode *self = node::ObjectWrap::Unwrap<DissectorNode>(info.This());
	self->m_dataSourceStorage->Set(property, value);
}

/*static*/ v8::Handle<v8::Value> DissectorNode::representationGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
	v8::HandleScope scope;
	DissectorNode *self = node::ObjectWrap::Unwrap<DissectorNode>(info.This());
	
	if(self->m_representation.IsEmpty()) {
		field_info *fi = PNODE_FINFO(self->m_node);
		char *temp = new char[strlen(fi->rep->representation)+2]; // TODO: avoid copy
		fixEscapes(fi->rep->representation, temp);
		self->m_representation = v8::Persistent<v8::String>::New(v8::String::New(temp));
		delete[] temp;
	}	
	
	return scope.Close(self->m_representation);
}

/*static*/ void DissectorNode::representationSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {
	v8::HandleScope scope;
	DissectorNode *self = node::ObjectWrap::Unwrap<DissectorNode>(info.This());
	self->m_representation.Dispose();
	self->m_representation = v8::Persistent<v8::Value>::New(value);
}

/*static*/ v8::Handle<v8::Value> DissectorNode::valueGetter(v8::Local<v8::String> property, const v8::AccessorInfo& info) {
	v8::HandleScope scope;
	DissectorNode *self = node::ObjectWrap::Unwrap<DissectorNode>(info.This());
	
	if(self->m_value.IsEmpty()) {
		field_info *fi = PNODE_FINFO(self->m_node);
    int showStringChopPos = 0;
    char *showString = proto_construct_match_selected_string(fi, self->m_edt);
		if (showString != NULL) {
			char *p = strstr(showString, "==");
			if(p) {
				showStringChopPos = (int)(p - showString) + 3;
			}

			if (showString[strlen(showString)-1] == '"') {
					showString[strlen(showString)-1] = '\0';
					showStringChopPos++;
			}

      char *theString = &(showString[showStringChopPos]);
      char *temp = new char[strlen(theString)+2]; // TODO: avoid copy
      fixEscapes(theString, temp);
      self->m_value = v8::Persistent<v8::String>::New(v8::String::New(temp));
      delete[] temp;
		}
	}
	
	return scope.Close(self->m_value);
}

/*static*/ void DissectorNode::valueSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {
	v8::HandleScope scope;
	DissectorNode *self = node::ObjectWrap::Unwrap<DissectorNode>(info.This());
	self->m_value.Dispose();
	self->m_value = v8::Persistent<v8::Value>::New(value);
}

DissectorNode::DissectorNode(DissectorNode *root, frame_data *fdata, epan_dissect_t *edt, proto_node *node) {
	m_fdata = fdata;
	if(root == NULL) {
		m_root = this;
	} else {
		m_root = root;
	}
  m_edt = edt;
  m_node = node;
	m_childStorage = v8::Persistent<v8::Object>::New(v8::Object::New());
	m_dataSourceStorage = v8::Persistent<v8::Object>::New(v8::Object::New());
}

DissectorNode::~DissectorNode() {
	m_representation.Dispose();
	m_value.Dispose();
	m_childStorage.Dispose();
	m_dataSourceStorage.Dispose();
	if(isRoot()) {
		epan_dissect_cleanup(m_edt);
	  frame_data_cleanup(m_fdata);
		delete m_edt;
		delete m_fdata;
	}
}

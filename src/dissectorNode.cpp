
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

/*static*/ v8::Persistent<v8::FunctionTemplate> DissectorNode::s_ct;

struct ChildenForEachData {
  v8::Local<v8::Object> _this;
  v8::Local<v8::Function> callback;
  v8::Local<v8::Object> result;
  DissectorNode* self;
};

/*static*/ void DissectorNode::Init(v8::Handle<v8::Object> target) {
  v8::HandleScope scope;

  v8::Local<v8::FunctionTemplate> t = v8::FunctionTemplate::New();
  s_ct = v8::Persistent<v8::FunctionTemplate>::New(t);
  s_ct->InstanceTemplate()->SetInternalFieldCount(1);
  NODE_SET_PROTOTYPE_METHOD(s_ct, "childenForEach", ChildenForEach);
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

/*static*/ v8::Local<v8::Value> DissectorNode::New(frame_data *fdata, epan_dissect_t *edt, proto_node *node, v8::Local<v8::Value> result, v8::Local<v8::Object> rawPacket, int root) {
  v8::Local<v8::Function> ctor = s_ct->GetFunction();
  v8::Local<v8::Object> obj = ctor->NewInstance();
  DissectorNode *self = new DissectorNode(fdata, edt, node, result, rawPacket, root);
  obj->SetPointerInInternalField(0, self);
  if(node == self->m_edt->tree) {
    obj->Set(v8::String::New("root"), v8::Boolean::New(true));
  }

  field_info *fi = PNODE_FINFO(node);
  if(fi) {
    obj->Set(v8::String::New("sizeInPacket"), v8::Integer::New(fi->length));
    obj->Set(v8::String::New("positionInPacket"), v8::Integer::New(getPositionInPacket(node, fi)));
    obj->Set(v8::String::New("abbreviation"), v8::String::New(fi->hfinfo->abbrev));

    if (fi->rep) {
      char *temp = new char[strlen(fi->rep->representation)+2]; // TODO: avoid copy
      fixEscapes(fi->rep->representation, temp);
      obj->Set(v8::String::New("representation"), v8::String::New(temp));
      delete[] temp;
		}

    // Show value
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
      obj->Set(v8::String::New("value"), v8::String::New(temp));
      delete[] temp;
		}
  }
  return obj;
}

DissectorNode::DissectorNode(frame_data *fdata, epan_dissect_t *edt, proto_node *node, v8::Local<v8::Value> result, v8::Local<v8::Object> rawPacket, int root) {
	m_fdata = fdata;
	m_root = root;
  m_edt = edt;
  m_node = node;
  m_result = result;
  m_rawPacket = rawPacket;
}

DissectorNode::~DissectorNode() {
	if(m_root) {
		epan_dissect_cleanup(m_edt);
	  frame_data_cleanup(m_fdata);
		delete m_edt;
		delete m_fdata;
	}
}

void DissectorNode::NotImplementedSetter(v8::Local<v8::String> property, v8::Local<v8::Value> value, const v8::AccessorInfo& info) {

}

void DissectorNode::ChildrenForEachItem(proto_node *node, gpointer data) {
  ChildenForEachData *pdata = (ChildenForEachData*)data;

	v8::Local<v8::Value> newNode = DissectorNode::New(pdata->self->m_fdata, pdata->self->m_edt, node, pdata->result, pdata->self->m_rawPacket, false);
	v8::Local<v8::Value> callbackArgs[4] = { pdata->result, pdata->_this, newNode, pdata->self->m_rawPacket };
	pdata->callback->Call(pdata->_this, 4, callbackArgs);
}

v8::Handle<v8::Value> DissectorNode::ChildenForEach(const v8::Arguments& args) {
  DissectorNode* self = ObjectWrap::Unwrap<DissectorNode>(args.This());

  if(args.Length() != 2) {
		return v8::ThrowException(v8::Exception::Error(v8::String::New("childenForEach takes 2 argument (object, callback).")));
	}

  // object argument
	if(!args[0]->IsObject()) {
		return v8::ThrowException(v8::Exception::Error(v8::String::New("First argument must contain an object.")));
	}
	v8::Local<v8::Object> result = v8::Local<v8::Object>::Cast(args[0]);

  // callback argument
	if(!args[1]->IsFunction()) {
		return v8::ThrowException(v8::Exception::Error(v8::String::New("Second argument must contain a callback.")));
	}
	v8::Local<v8::Function> callback = v8::Local<v8::Function>::Cast(args[1]);

  ChildenForEachData data;
  data._this = args.This();
  data.self = self;
  data.callback = callback;
  data.result = result;
  proto_tree_children_foreach(self->m_node, ChildrenForEachItem, &data);

  return v8::Undefined();
}

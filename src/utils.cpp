
#include <v8.h>
#include <stdlib.h>
#include "utils.h"

double getNumberFromV8Object(v8::Local<v8::Object> &obj, const char *key, double def) {
  v8::Local<v8::Value> v = obj->Get(v8::String::New(key));
  if(v->IsNumber()) {
    return v->ToNumber()->Value();
  }
  if(v->IsString()) {
    v8::String::AsciiValue asciiVal(v);
    return atof(*asciiVal);
  }
  return def;
}

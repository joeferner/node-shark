
#ifndef _utils_h_
#define _utils_h_

#include <v8.h>

#define REQ_OBJECT_ARG(I, VAR)                                                                                 \
  if (args.Length() <= (I) || !args[I]->IsObject())                                                            \
    return v8::ThrowException(v8::Exception::Error(v8::String::New("Argument " #I " must be an object"))); \
  v8::Local<v8::Object> VAR = v8::Local<v8::Object>::Cast(args[I]);

#define REQ_NUMBER_ARG(I, VAR)                                                                                 \
  if (args.Length() <= (I) || !args[I]->IsNumber())                                                            \
    return v8::ThrowException(v8::Exception::Error(v8::String::New("Argument " #I " must be a number")));      \
  v8::Local<v8::Number> VAR = v8::Local<v8::Number>::Cast(args[I]);

double getNumberFromV8Object(v8::Local<v8::Object> &obj, const char *key, double def);

void strtrim(char *str);

#endif

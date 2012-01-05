
#ifndef _utils_h_
#define _utils_h_

#define REQ_OBJECT_ARG(I, VAR)                                                                                 \
  if (args.Length() <= (I) || !args[I]->IsObject())                                                            \
    return v8::ThrowException(v8::Exception::Error(v8::String::New("Argument " #I " must be an object"))); \
  v8::Local<v8::Object> VAR = v8::Local<v8::Object>::Cast(args[I]);

#endif

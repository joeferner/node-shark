
#ifndef _utils_h_
#define _utils_h_

//#define BENCHMARK

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

#ifdef BENCHMARK
  #include <time.h>
  #define BENCHMARK_GLOBAL_DEF()     BENCHMARK_DEF(total)
  #define BENCHMARK_DEF(NAME)        clock_t g_benchmark_##NAME##_start = 0; \
                                     clock_t g_benchmark_##NAME = 0; \
                                     int g_benchmark_##NAME##_count = 0;
  #define BENCHMARK_DEF_EXTERN(NAME) extern clock_t g_benchmark_##NAME##_start; \
                                     extern clock_t g_benchmark_##NAME; \
                                     extern int g_benchmark_##NAME##_count;
  #define BENCHMARK_GLOBAL_START()   BENCHMARK_START(total)
  #define BENCHMARK_GLOBAL_END()     BENCHMARK_END(total)
  #define BENCHMARK_START(NAME)      g_benchmark_##NAME##_start = clock();
  #define BENCHMARK_END(NAME)        g_benchmark_##NAME += clock() - g_benchmark_##NAME##_start; \
                                     g_benchmark_##NAME##_count++;
  #define BENCHMARK_PRINT_START()    printf("%35s    %12s %8s %10s %10s\n", "Name", "Total Time", "Count", "Time per", "Percent"); \
                                     printf("%35s    %12s %8s %10s %10s\n", "---------------------------------", "------------", "--------", "----------", "----------");
  #define BENCHMARK_PRINT_END()      BENCHMARK_PRINT(total) \
                                     printf("\n");
  #define BENCHMARK_PRINT(NAME)      printf("%35s -> %12f %8d %10f %9.1f%%\n", #NAME, (float)g_benchmark_##NAME / (float)CLOCKS_PER_SEC, g_benchmark_##NAME##_count, (float)g_benchmark_##NAME / CLOCKS_PER_SEC / (float)g_benchmark_##NAME##_count, (float)g_benchmark_##NAME / (float)g_benchmark_total * 100.0f);
#else
  #define BENCHMARK_GLOBAL_DEF()
  #define BENCHMARK_DEF(NAME)
  #define BENCHMARK_DEF_EXTERN(NAME)
  #define BENCHMARK_GLOBAL_START()
  #define BENCHMARK_GLOBAL_END()
  #define BENCHMARK_START(NAME)
  #define BENCHMARK_END(NAME)
  #define BENCHMARK_PRINT_START()
  #define BENCHMARK_PRINT_END()
  #define BENCHMARK_PRINT(NAME)
#endif

#endif

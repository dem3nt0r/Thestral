cmake_minimum_required(VERSION 3.20)
project(Plimpy LANGUAGES CXX)
find_package(Threads REQUIRED)
if(NOT WIN32)
  message(FATAL_ERROR "Configure with a Windows x86 or x64 compiler")
endif()

option(PLIMPY_BUILD_TESTS "Build controlled architecture integration tests" OFF)
if(PLIMPY_BUILD_TESTS)
  enable_testing()
  add_executable(PlimpyArchitectureTarget Tests/ArchitectureTarget.cpp)
  add_executable(PlimpyArchitectureTests
    Tests/ArchitectureTests.cpp
    ProcessHelper.cpp
    ThreadStack.cpp
    PeImage.cpp
    DllUnloader.cpp
    ConsoleHelper.cpp
    WorkerPool.cpp
  )
  foreach(test_target PlimpyArchitectureTarget PlimpyArchitectureTests)
    target_compile_features(${test_target} PRIVATE cxx_std_17)
    target_compile_definitions(${test_target} PRIVATE UNICODE _UNICODE)
    target_include_directories(${test_target} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    if(NOT MSVC)
      target_link_options(${test_target} PRIVATE -municode -static)
    endif()
  endforeach()
  target_link_libraries(PlimpyArchitectureTests PRIVATE psapi dbghelp advapi32 shlwapi Threads::Threads)
  add_executable(PlimpyWorkerPoolTests Tests/WorkerPoolTests.cpp WorkerPool.cpp)
  target_compile_features(PlimpyWorkerPoolTests PRIVATE cxx_std_17)
  target_include_directories(PlimpyWorkerPoolTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(PlimpyWorkerPoolTests PRIVATE Threads::Threads)
  add_test(NAME PlimpyWorkerPool COMMAND PlimpyWorkerPoolTests)
  set_tests_properties(PlimpyWorkerPool PROPERTIES TIMEOUT 30)
  add_executable(PlimpyConsoleOutputTests
    Tests/ConsoleOutputTests.cpp ConsoleHelper.cpp WorkerPool.cpp)
  target_compile_features(PlimpyConsoleOutputTests PRIVATE cxx_std_17)
  target_include_directories(PlimpyConsoleOutputTests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(PlimpyConsoleOutputTests PRIVATE Threads::Threads)
  if(NOT MSVC)
    target_link_options(PlimpyConsoleOutputTests PRIVATE -municode -static)
  endif()
  add_test(NAME PlimpyConsoleOutput
    COMMAND PlimpyConsoleOutputTests ${CMAKE_CURRENT_BINARY_DIR}/ConsoleOutput.txt)
  set_tests_properties(PlimpyConsoleOutput PROPERTIES TIMEOUT 30)
  add_test(NAME PlimpyArchitectureNative
    COMMAND PlimpyArchitectureTests $<TARGET_FILE:PlimpyArchitectureTarget>)
  set_tests_properties(PlimpyArchitectureNative PROPERTIES TIMEOUT 30)
endif()
add_executable(Plimpy
  ConsoleHelper.cpp
  ComScanner.cpp
  DllUnloader.cpp
  FileMetadata.cpp
  InjectionScanner.cpp
  Plimpy.cpp
  PeImage.cpp
  ThreadStack.cpp
  ProcessHelper.cpp
  SignatureVerifier.cpp
  UnsignedScanner.cpp
  WorkerPool.cpp
)
target_compile_features(Plimpy PRIVATE cxx_std_17)
target_compile_definitions(Plimpy PRIVATE UNICODE _UNICODE)
target_link_libraries(Plimpy PRIVATE psapi dbghelp wintrust crypt32 advapi32 shlwapi Threads::Threads)
if(MSVC)
  target_sources(Plimpy PRIVATE App.manifest)
  target_compile_options(Plimpy PRIVATE /W4 /permissive-)
else()
  enable_language(RC)
  target_sources(Plimpy PRIVATE App.rc)
  target_include_directories(Plimpy PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_options(Plimpy PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-Wall;-Wextra;-Wno-cast-function-type>)
  target_link_options(Plimpy PRIVATE -municode -static)
endif()

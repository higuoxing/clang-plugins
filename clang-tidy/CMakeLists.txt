set(LLVM_LINK_COMPONENTS
  Support
  FrontendOpenMP
)

add_library(PostgresTidyModule SHARED
  PostgresTidyModule.cpp
  ListFreeCheck.cpp
  ReturnInPgTryBlockCheck.cpp
)

target_link_libraries(PostgresTidyModule
  PRIVATE
  "$<$<PLATFORM_ID:Darwin>:-undefined dynamic_lookup>"
)

# We need to make sure it's a loadable module
set_target_properties(PostgresTidyModule PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN 1
)

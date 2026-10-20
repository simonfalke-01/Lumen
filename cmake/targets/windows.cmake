# windows specific target definitions
set_target_properties(lumen PROPERTIES
        LINK_SEARCH_START_STATIC 1
        OUTPUT_NAME "Lumen")
set_target_properties(lumensvc PROPERTIES OUTPUT_NAME "lumensvc")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".dll")
find_library(ZLIB ZLIB1)
list(APPEND LUMEN_EXTERNAL_LIBRARIES
        $<TARGET_OBJECTS:lumen_rc_object>
        Windowsapp.lib
        Wtsapi32.lib
        version.lib)

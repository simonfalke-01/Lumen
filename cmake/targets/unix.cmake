# unix specific target definitions
# put anything here that applies to both linux and macos

# Keep the historical CMake target name for downstream build integrations while
# publishing the application under its Lumen executable identity.
set_target_properties(sunshine PROPERTIES OUTPUT_NAME "lumen")

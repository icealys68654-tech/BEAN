cmake_minimum_required(VERSION 3.20)
project(BEAN LANGUAGES NONE)
find_program(NPM_EXECUTABLE npm REQUIRED)
find_program(PYTHON_EXECUTABLE NAMES python3 python REQUIRED)
add_custom_target(bean_install COMMAND npm install WORKING_DIRECTORY "\${CMAKE_SOURCE_DIR}")
add_custom_target(bean_build COMMAND npm run build WORKING_DIRECTORY "\${CMAKE_SOURCE_DIR}")
add_custom_target(bean_test
  COMMAND npm test
  COMMAND "\${PYTHON_EXECUTABLE}" -m unittest discover -s ops/windows/ids/tests -v
  WORKING_DIRECTORY "\${CMAKE_SOURCE_DIR}")
add_custom_target(bean_ids_help
  COMMAND "\${PYTHON_EXECUTABLE}" ops/windows/ids/scanner.py --help
  WORKING_DIRECTORY "\${CMAKE_SOURCE_DIR}")

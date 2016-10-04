unamestr=`uname -s`
if [[ $unamestr == "Darwin" ]]; then
  ./scripts/unix/install_xed_osx.sh
elif [[ $unamestr == "Linux" ]]; then
  ./scripts/unix/install_xed_linux.sh;
else
  echo "Couldn't tell if we're running on OS X or linux, please run install_xed_linux.sh or install_xed_osx.sh manually"
fi

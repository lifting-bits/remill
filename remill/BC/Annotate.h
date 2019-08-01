/*
 * Copyright (c) 2019 Trail of Bits, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <string>
#include <vector>

#include <llvm/IR/Module.h>
#include <llvm/IR/Metadata.h>

namespace remill {

// For all function holds that Kind should have two static strings
// * metadata_kind that is the identifier of metadata
// * metadata_value that is the value that identifies the Kind itself


struct BaseFunction {
  static const std::string metadata_kind;
  // Each class that inherits from some parent class appends its own metadata_value string with dot
  // to the parents one, therefore it is possible for search to easily include all subclasses as well
  static const std::string metadata_value;
};

// Unfortunately we must define the values of static vars in .cpp file
#define DECLARE_FUNC_ORIGIN_TYPE(children, parent) \
struct children : parent { \
  static const std::string metadata_value; \
}

DECLARE_FUNC_ORIGIN_TYPE( LiftedFunction, BaseFunction );
DECLARE_FUNC_ORIGIN_TYPE( EntrypointFunction, BaseFunction );
DECLARE_FUNC_ORIGIN_TYPE( ExternalFunction, BaseFunction );
DECLARE_FUNC_ORIGIN_TYPE( AbiLibraries, ExternalFunction );
DECLARE_FUNC_ORIGIN_TYPE( CFGExternal, ExternalFunction );
DECLARE_FUNC_ORIGIN_TYPE( Helper, BaseFunction );
DECLARE_FUNC_ORIGIN_TYPE( RemillHelper, Helper );
DECLARE_FUNC_ORIGIN_TYPE( McSemaHelper, Helper );

// Give function Kind
template< typename Kind >
void Annotate( llvm::Function *func ) {
  auto &C = func->getContext();
  auto node = llvm::MDNode::get( C, llvm::MDString::get( C, LiftedFunction::metadata_value ) );
  func->setMetadata( LiftedFunction::metadata_kind, node );
}

// Return list of functions that are of chosen kind
template< typename Kind, typename Container = std::vector< llvm::Function * > >
Container GetFunctionsByOrigin( llvm::Module &module, const Kind & ) {

  Container result;

  for ( auto &func : module ) {

    auto metadata_node = func.getMetadata( Kind::metadata_kind );
    // There should be exactly one string there
    if ( !metadata_node || metadata_node->getNumOperands() != 1 ) {
      continue;
    }

    if ( auto message = llvm::dyn_cast< llvm::MDString >( metadata_node->getOperand( 0 ) ) ) {
      if ( message->getString().contains( Kind::metadata_value ) ) {
        result.insert( result.end(), &func );
      }
    }
  }
  return result;
}

// Return list of functions that are of chosen kind
template< typename Kind, typename Container = std::vector< llvm::Function * > >
Container GetFunctionsByOrigin( llvm::Module &module ) {
  return GetFunctionsByOrigin( module, Kind{} );
}

} // namespace remill

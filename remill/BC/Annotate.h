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
#include <utility>
#include <vector>

#include <llvm/IR/Module.h>
#include <llvm/IR/Metadata.h>

#include <glog/logging.h>

namespace remill {

// For all function holds that OriginType should have two static strings
// * metadata_kind that is the identifier (kind) of metadata
// * metadata_value that is the value that identifies the OriginType itself


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

#undef DECLARE_FUNC_ORIGIN_TYPE

// Note(Aiethel): I tried to make them static methods and while it works it is not really worth

template< typename OriginType >
bool Contains( llvm::MDString *node ) {
  return node && node->getString().contains( OriginType::metadata_value );
}

template< typename OriginType >
llvm::MDNode *GetNode( llvm::Function *func ) {

  auto metadata_node = func->getMetadata( OriginType::metadata_kind );

  // There should be exactly one string there
  if ( !metadata_node || metadata_node->getNumOperands() != 1 ) {
    return nullptr;
  }

  auto metadata_s = llvm::dyn_cast< llvm::MDString >( metadata_node->getOperand( 0 ) );
  return ( Contains< OriginType >( metadata_s ) ) ? metadata_node : nullptr;
}

template< typename OriginType >
bool Remove( llvm::Function *func ) {
  auto node = GetNode< OriginType >( func );
  if ( !node ) {
    return false;
  }

  func->eraseMetadata( node->getMetadataID() );
  return true;
}

// Give function OriginType
template< typename OriginType >
void Annotate( llvm::Function *func  ) {
  auto &C = func->getContext();
  LOG( INFO ) << "Annotating: " << func->getName().str() << ": " << OriginType::metadata_kind
              << " -> " << OriginType::metadata_value << std::endl;
  auto node = llvm::MDNode::get( C, llvm::MDString::get( C, OriginType::metadata_value ) );
  func->setMetadata( OriginType::metadata_kind, node );
}

template< typename OriginType >
bool HasOriginType( llvm::Function *func ) {
  return GetNode< OriginType >( func );
}

template< typename Type, typename Second, typename ...OriginTypes >
bool HasOriginType( llvm::Function *func ) {
  return HasOriginType< Type >( func ) || HasOriginType< Second, OriginTypes... >( func );
}

// Return list of functions that are of chosen OriginType
template< typename OriginType, typename Container = std::vector< llvm::Function * > >
Container GetFunctionsByOrigin( llvm::Module &module ) {

  Container result;

  for ( auto &func : module ) {
    if ( HasOriginType< OriginType >( &func ) ) {
      // Method that is both in std::set and std::vector
      result.insert( result.end(), &func );
    }
  }
  return result;
}

template< typename OriginType >
void ChangeOriginType( llvm::Function *func ) {
  Annotate< OriginType >( func );
}

template< typename OriginType, typename OldType >
bool ChangeOriginType( llvm::Function *func ) {
  if ( HasOriginType< OldType >( func ) ) {
    ChangeOriginType< OriginType >( func );
    return true;
  }
  return false;
}
/* Functions that "tie" together two functions via specific metada:
 * Both of them will contain metadata of specified kind, that is the other function.
 * This is useful for example to tie entrypoints and their corresponding sub_ functions
 */


// Default kind to be used, user is free to choose different, for example if each function
// is supposed to be part of multiple pairs
const std::string TieKind = "remill.function.tie";

// Get node that is holding the tie information
llvm::MDNode *TieNode( llvm::Function *func, const std::string &kind = TieKind );

bool IsTied( llvm::Function *func, const std::string& kind = TieKind );

// Add metadata to first with information about second
llvm::MDNode *TieFunction( llvm::Function *first, llvm::Function *second,
                           const std::string& kind = TieKind );

std::pair< llvm::MDNode *, llvm::MDNode * >
TieFunctions( llvm::Function *first, llvm::Function *second, const std::string &kind = TieKind );

// Get function that is tied to func, or nullptr if there is no such function
llvm::Function *GetTied( llvm::Function *func, const std::string &kind = TieKind );

} // namespace remill

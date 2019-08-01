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

#include "Annotate.h"

namespace remill {

const std::string BaseFunction::metadata_value = "base";

const std::string BaseFunction::metadata_kind = "remill.function.type";

const std::string LiftedFunction::metadata_value = BaseFunction::metadata_value + "." + "lifted";

const std::string EntrypointFunction::metadata_value = BaseFunction::metadata_value + "." +
                                                       "entrypoint";

const std::string ExternalFunction::metadata_value = BaseFunction::metadata_value + "." +
                                                     "external";

const std::string AbiLibraries::metadata_value = ExternalFunction::metadata_value + "." +
                                                 "abilibraries";

const std::string CFGExternal::metadata_value = ExternalFunction::metadata_value + "." +
                                                "cfgexternal";


const std::string Helper::metadata_value = BaseFunction::metadata_value + "." + "helper";


const std::string RemillHelper::metadata_value = Helper::metadata_value + "." +
                                                  "remill";

const std::string McSemaHelper::metadata_value = Helper::metadata_value + "." +
                                                 "mcsema";


llvm::MDNode *TieNode( llvm::Function *func, const std::string &kind ) {
  return func->getMetadata( kind );
}

bool IsTied( llvm::Function *func, const std::string& kind ) {
  return TieNode( func, kind );
}

llvm::MDNode *TieFunction( llvm::Function *first, llvm::Function *second,
                           const std::string& kind ) {
  auto &C = first->getContext();
  auto node = llvm::MDNode::get( C, llvm::ConstantAsMetadata::get( second ) );
  first->setMetadata( kind, node );
  return node;
}

std::pair< llvm::MDNode *, llvm::MDNode * >
TieFunctions( llvm::Function *first, llvm::Function *second, const std::string &kind ) {
  LOG_IF( FATAL, IsTied( first ) || IsTied( second ) )
      << "Tried to tie already tied functions " << first->getName().str()
      << " to " << second->getName().str();

  return { TieFunction( first, second, kind ), TieFunction( second, first, kind ) };
}


llvm::Function *GetTied( llvm::Function *func, const std::string &kind ) {
  auto node = TieNode( func, kind );
  if ( !node || node->getNumOperands() != 1 ) {
    return nullptr;
  }

  auto casted = llvm::dyn_cast< llvm::ConstantAsMetadata >( node->getOperand( 0 ) );

  // For now we crash here, since this should not happen
  LOG_IF( FATAL, !casted )
      << "Was not able to cast llvm::MDNode to llvm::ConstantAsMetadata, possible error.";

  return llvm::dyn_cast< llvm::Function >( casted->getValue() );
}

} // namespace remill

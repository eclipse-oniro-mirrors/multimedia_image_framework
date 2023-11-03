/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef HWE_LIST_H
#define HWE_LIST_H

namespace OHOS {
namespace ImagePlugin {
// generic node function pointer type for queue
typedef int32_t *(*HWE_GenericFunc)(int32_t *funcArg);

// generic node struct type
typedef struct HWE_NodeType {
    void *element;             // next data pointer
    struct HWE_NodeType *next; // next node pointer
} HWE_Node;

// job node struct type
typedef struct HWE_JobNodeType {
    HWE_GenericFunc func;         // job node function
    int32_t *funcArg;             // the argument of job node function
    struct HWE_JobNodeType *next; // next job node pointer
} HWE_JobNode;

void HWE_Free(HWE_JobNode *node)
{
    if (node != nullptr) {
        free(node);
        node = nullptr;
    }
}

/*
 * free all nodes of list
 * nodeType: node type name, e.g. HWE_Node, HWE_JobNode
 */
void HWE_ListFreeAll(HWE_JobNode*& head, HWE_JobNode*& tail)
{
    while (head) {
        HWE_JobNode* tmpNode = head;
        if (tmpNode->next) {
            head = tmpNode->next;
        } else {
            head = nullptr;
        }
        HWE_Free(tmpNode);
    }
    tail = nullptr;
}

/*
 * push node to tail of list
 * macro don't allocate node memory, caller is responsible for node memory allocation
 */
void HWE_ListPushTail(HWE_JobNode*& head, HWE_JobNode*& tail, HWE_JobNode* node)
{
    if (!tail) {
        head = node;
        tail = node;
    } else {
        tail->next = node;
        tail = node;
    }
}

/*
 * push node from tail of list
 * macro don't free node memory, caller is responsible for node memory free
 */
void HWE_ListPopHead(HWE_JobNode*& head, HWE_JobNode*& tail, HWE_JobNode*& node)
{
    if (!head) {
        node = nullptr;
    } else {
        node = head;
        if (node->next) {
            head = node->next;
            node->next = nullptr;
        } else {
            head = nullptr;
            tail = nullptr;
            node->next = nullptr;
        }
    }
}
} // namespace ImagePlugin
} // namespace OHOS
#endif // HWE_LIST_H
from Config.Sys_Config import DECISION_MODEL_PATH, ENGINE_UNIT_CONTEXT, ENGINE_UNIT_THREADS, ENGINE_UNIT_GPU_LAYERS, ENGINE_UNIT_TEMPERATURE
from llama_cpp import Llama
import json

# =============================================
# SINGLE PLACEHOLDER TOOL
# =============================================

def placeholder_tool(input: str):
    return f"Tool executed with input: {input}"

TOOL_REGISTRY = {
    "placeholder_tool": placeholder_tool
}

# =============================================
# TOOL SCHEMA
# =============================================

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "placeholder_tool",
            "description": "Placeholder tool for routing",
            "parameters": {
                "type": "object",
                "properties": {
                    "input": {
                        "type": "string"
                    }
                },
                "required": ["input"]
            }
        }
    }
]

# =============================================
# LOAD MODEL
# =============================================

llm = Llama(
    model_path=DECISION_MODEL_PATH,  # <-- CHANGE
    n_ctx=ENGINE_UNIT_CONTEXT,
    n_threads=ENGINE_UNIT_THREADS,
    n_gpu_layers=-ENGINE_UNIT_GPU_LAYERS,
    temperature=ENGINE_UNIT_TEMPERATURE,
    verbose=False
)

# =============================================
# TOOL ROUTER
# =============================================

def run(task: str):
    response = llm.create_chat_completion(
        messages=[
            {
                "role": "system",
                "content": "You are a tool router. Always call the tool."
            },
            {
                "role": "user",
                "content": task
            }
        ],
        tools=TOOLS,
        tool_choice="auto"
    )

    message = response["choices"][0]["message"]

    if "tool_calls" not in message:
        raise RuntimeError("No tool call")

    call = message["tool_calls"][0]
    args = json.loads(call["function"]["arguments"])

    return TOOL_REGISTRY[call["function"]["name"]](**args)

# =============================================
# EXAMPLE
# =============================================

if __name__ == "__main__":
    result = run("Send this to the tool")
    print(result)

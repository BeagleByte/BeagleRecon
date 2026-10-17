from config import Config

class ModelFactory:
    """Builds the AG2 llm_config for the local Ollama server."""

    def __init__(self, config: Config):
        self.config = config

    def model(self) -> str:
        """Chat model for the agents: agent_model first, chat_model as fallback."""
        return self.config.agent_model or self.config.chat_model

    def build_llm_config(self) -> dict:
        return {
            "config_list": [
                {
                    "model": self.model(),
                    "api_type": "ollama",
                    "client_host": self.config.ollama_base_url,
                    # Pass the tool schemas natively to Ollama instead of the
                    # manual two-step JSON instruction - required for
                    # gemma3-4k-tools to emit proper tool_calls with arguments.
                    "native_tool_calls": True,
                }
            ]
        }


# Model Configuration for EnIGMA+

This document explains how to configure models in EnIGMA+ using the new YAML-based configuration system.

## Overview

EnIGMA+ now uses a centralized YAML configuration file (`models_config.yaml`) to define all supported models and their properties. This makes it easy to add new models without modifying the Python code.

## Configuration Structure

The configuration file is organized by provider:

- `openai_models` - OpenAI and OpenAI-compatible models
- `anthropic_models` - Anthropic Claude models  
- `groq_models` - Groq-hosted models
- `together_models` - Together AI models
- `deepseek_models` - DeepSeek-specific models
- `bedrock_models` - Amazon Bedrock models
- `special_models` - Human, replay, and test models

Each provider section also has an optional `_shortcuts` section for friendly aliases.

## Model Properties

Each model can have the following properties:

### Required
- `max_context` - Maximum context window size in tokens

### Optional (defaults to 0.0 for turn-based evaluation)
- `cost_per_input_token` - Cost per input token in USD
- `cost_per_output_token` - Cost per output token in USD
- `max_tokens` - Maximum tokens to generate (for models that need this)

## Adding a New Model

### 1. Add to the appropriate provider section:

```yaml
openai_models:
  my-new-model:
    max_context: 32768
    cost_per_input_token: 1e-06
    cost_per_output_token: 2e-06
```

### 2. Optionally add a shortcut:

```yaml
openai_shortcuts:
  my-model: my-new-model
```

### 3. For local/custom models (no pricing):

```yaml
openai_models:
  "/path/to/my/local/model":
    max_context: 32768
    # cost defaults to 0.0
```

## Model Types and Providers

### OpenAI Models
- All GPT models (GPT-3.5, GPT-4, GPT-4o, O1)
- Local and fine-tuned models
- Custom model paths
- DeepSeek reasoner models

### Anthropic Models  
- Claude Instant, Claude 2.x, Claude 3.x series
- Claude 3.5 Sonnet

### Groq Models
- Llama models (3, 3.1 series)
- Gemma models
- Mixtral models

### Together AI Models
- Llama 2 series
- Mistral models
- RedPajama models

### DeepSeek Models
- DeepSeek Coder
- Other DeepSeek-specific models

### Bedrock Models
- AWS Bedrock-hosted models
- Cross-region Anthropic models

## Turn-Based Evaluation

EnIGMA+ focuses on turn-based evaluation rather than cost-based limits. This means:

- **Pricing is optional** - Models default to 0.0 cost
- **Step limits are used** - `per_instance_step_limit` parameter controls turns
- **Fair comparison** - All models get the same number of interaction turns

## Examples

### Adding a new OpenAI-compatible model:
```yaml
openai_models:
  gpt-4-custom:
    max_context: 128000
    cost_per_input_token: 1e-05
    cost_per_output_token: 3e-05

openai_shortcuts:
  gpt4-custom: gpt-4-custom
```

### Adding a free local model:
```yaml
openai_models:
  "/home/user/my-local-model":
    max_context: 32768
    # No cost specified - defaults to 0.0

openai_shortcuts:
  my-local: "/home/user/my-local-model"
```

### Adding a new provider model:
```yaml
groq_models:
  new-groq-model:
    max_context: 8192
    # Free model - no cost specified

groq_shortcuts:
  new-groq: new-groq-model
```

## Usage

Once configured, use models with their name or shortcut:

```bash
# Using full model name
python run.py --model_name gpt-4-1106-preview

# Using shortcut
python run.py --model_name gpt4

# Using custom model
python run.py --model_name my-local

# Turn-based evaluation (EnIGMA+ default)
python run.py --model_name gpt4 --per_instance_step_limit 40
```

## Benefits

1. **No code changes needed** - Add models without touching Python files
2. **Centralized configuration** - All model info in one place
3. **Pricing optional** - Perfect for turn-based evaluation
4. **Easy maintenance** - Update model pricing/context without code changes
5. **Flexible shortcuts** - Create friendly aliases for complex model names
6. **Provider organization** - Models grouped by API provider for clarity

## Migration

If you have custom models from the old system:
1. Add them to the appropriate section in `models_config.yaml`
2. Set `cost_per_input_token: 0.0` and `cost_per_output_token: 0.0` for free models
3. Add shortcuts if desired
4. Test with `python run.py --model_name your-model --help` 
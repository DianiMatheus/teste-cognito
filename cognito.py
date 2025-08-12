# https://brlink-credito.streamlit.app/
import streamlit as st
import boto3
import json
from boto3.dynamodb.conditions import Attr
import time
from botocore.exceptions import ClientError

# --- Configurações AWS DynamoDB ---
DYNAMODB_TABLE_NAME = "pod-jsonresponse"

# --- Configurações AWS Bedrock ---
MODEL_HAIKU = 'us.anthropic.claude-3-5-haiku-20241022-v1:0'
MODEL_HAIKU_2 = 'us.anthropic.claude-3-haiku-20240307-v1:0'

# --- Configurações AWS Cognito ---
COGNITO_APP_CLIENT_ID = "7qvtg7i81gqcnoh18f78m58q31"

# --- Inicialização de clientes ---
@st.cache_resource
def get_aws_session():
    creds = st.secrets["aws"]
    return boto3.Session(
        aws_access_key_id=creds["access_key_id"],
        aws_secret_access_key=creds["secret_access_key"],
        region_name=creds.get("region", "us-east-1"),
    )

@st.cache_resource
def get_dynamodb_table():
    session = get_aws_session()
    dynamodb = session.resource("dynamodb")
    return dynamodb.Table(DYNAMODB_TABLE_NAME)

@st.cache_resource
def get_bedrock_client():
    return get_aws_session().client("bedrock-runtime")

@st.cache_resource
def get_cognito_client():
    return get_aws_session().client("cognito-idp")


# --- Funções de autenticação Cognito ---
def cognito_login(username, password):
    client = get_cognito_client()
    try:
        resp = client.initiate_auth(
            ClientId=COGNITO_APP_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
        
        if resp.get("ChallengeName") == "NEW_PASSWORD_REQUIRED":
            st.session_state.cognito_challenge = {
                "type": "NEW_PASSWORD_REQUIRED",
                "session": resp["Session"],
                "username": username,
            }
            st.session_state.authenticated = False
            return "CHALLENGE", None

        tokens = resp["AuthenticationResult"]
        st.session_state.authenticated = True
        st.session_state.username = username
        st.session_state.tokens = tokens
        st.session_state.auth_error = None
        st.session_state.cognito_challenge = None
        return True, None

    except ClientError as e:
        code = e.response["Error"].get("Code", "Error")
        msg  = e.response["Error"].get("Message", "")
        st.session_state.authenticated = False
        st.session_state.auth_error = f"{code}: {msg}"
        return False, st.session_state.auth_error

# Redefinir a senha no primeiro login
def cognito_complete_new_password(new_password: str):
    challenge = st.session_state.cognito_challenge
    if not challenge or challenge.get("type") != "NEW_PASSWORD_REQUIRED":
        return False, "Nenhum desafio pendente."

    client = get_cognito_client()
    try:
        resp = client.respond_to_auth_challenge(
            ClientId=COGNITO_APP_CLIENT_ID,
            ChallengeName="NEW_PASSWORD_REQUIRED",
            Session=challenge["session"],
            ChallengeResponses={
                "USERNAME": challenge["username"],
                "NEW_PASSWORD": new_password
            },
        )
        tokens = resp["AuthenticationResult"]
        st.session_state.authenticated = True
        st.session_state.username = challenge["username"]
        st.session_state.tokens = tokens
        st.session_state.auth_error = None
        st.session_state.cognito_challenge = None
        return True, None

    except ClientError as e:
        code = e.response["Error"].get("Code", "Error")
        msg  = e.response["Error"].get("Message", "")
        return False, f"{code}: {msg}"

# --- Helpers DynamoDB ---
def fetch_all_names():
    table = get_dynamodb_table()
    resp = table.scan(
        ProjectionExpression="#n",
        ExpressionAttributeNames={"#n": "_nome_index"}
    )
    items = resp.get("Items", [])
    return sorted({item["_nome_index"] for item in items if "_nome_index" in item})

def fetch_all_by_name(name: str):
    table = get_dynamodb_table()
    resp = table.scan(
        FilterExpression=Attr("_nome_index").eq(name.upper())
    )
    return resp.get("Items", [])

# --- AGENTE 1: Resumo JSON POD ---
def agente_1_resumo_pod(json_data: str) -> str:
    system_prompt = f"""
Contexto: Você é um Assistente de Crédito que recebeu um JSON com o resultado de uma análise de crédito:

{json_data}

OBJETIVO: Resumir as informações de crédito do cliente em formato JSON.

INTRUÇÕES:
1. Extrair todas as variáveis do array "features":
   - Percorra COMPLETAMENTE o array "features" 
   - Para cada objeto no array, extraia apenas os campos "feature" e "value"
   - NÃO OMITA NENHUMA feature, mesmo que pareça irrelevante
2. Extrair caminho de decisão do array "full_log":
   - Percorra COMPLETAMENTE o array "full_log" 
   - Para cada nó, extraia os campos "feature" e "value"
   - NÃO OMITA NENHUM passo do caminho de decisão

FORMATO DE SAÍDA:
Retorne APENAS um objeto JSON sem nenhum texto fora do JSON, com as seguintes variáveis

- "features": lista de objetos com "feature" e "value"
- "decision_path": lista de objetos com "feature" e "value" 
- "decision_status": string com o status da decisão
- "credit_score": número com o score de crédito
- "decision_reason": string com o motivo principal da decisão
- "request_date": string com a data da análise no formato "dd/mm/yyyy"
- "request_time": string com a hora da análise no formato "HH:MM"

Não inclua nenhum texto fora do JSON.
"""
    user_message = """
    Extraia todas as informações solicitadas e retorne apenas o JSON estruturado conforme especificado.
    """

    client = get_bedrock_client()
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": user_message}]}
        ],
        "max_tokens": 4096,
        "temperature": 0.4
    })
    resp = client.invoke_model(
        modelId=MODEL_HAIKU_2,
        body=body,
        contentType="application/json",
        accept="application/json"
    )
    resp_body = json.loads(resp["body"].read())
    text = resp_body["content"][0]["text"].strip()
    
    try:
        json.loads(text)
        return text
    except json.JSONDecodeError:
        error_json = {
            "erro": "Falha ao processar resposta do agente",
            "resposta_original": text
        }
        return json.dumps(error_json, ensure_ascii=False)

# --- AGENTE 2: Resumo JSON Externo ---
def agente_2_resumo_externo(json_data: str) -> str:
    system_prompt = f"""
Contexto: Você é um Assistente de Crédito que recebeu um JSON com o resultado de uma análise de crédito:

{json_data}

OBJETIVO: Resumir as informações de crédito do cliente em formato JSON.

INTRUÇÕES:
1. Listar as features mais importantes
2. Algumas variáveis são especialmente importantes:
   - possivelProfissao
   - possivelEscolaridade
   - personaDemografica
   - classeEconomica
   - score
   - mensagemScore
   - personaCredito
   - personaDigital
   - ultimaEmpresaLigada
   - pessoasLigadas
   - sociedades
3. Não liste:
    - sexo
    - cpf
    - nome
    - data de nascimento
    - endereço
    - geração
    - emails
    - telefones
    - situação cadastral
    - se é politicamente exposta
    - propensão de pagamento

FORMATO DE SAÍDA:
Retorne APENAS um objeto JSON válido, com cada variável extraída como chave e seu valor correspondente. 
Não inclua nenhum texto fora do JSON.
"""
    user_message = """
    Extraia as Variáveis mais importantes encontradas e retorne apenas o JSON estruturado.
    """

    client = get_bedrock_client()
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": user_message}]}
        ],
        "max_tokens": 4096,
        "temperature": 0.4
    })
    resp = client.invoke_model(
        modelId=MODEL_HAIKU_2,
        body=body,
        contentType="application/json",
        accept="application/json"
    )
    resp_body = json.loads(resp["body"].read())
    text = resp_body["content"][0]["text"].strip()

    try:
        data = json.loads(text)
        if "data_da_analise" not in data:
            data["data_da_analise"] = None
        if "status_de_decisao" not in data:
            data["status_de_decisao"] = None
        return json.dumps(data, ensure_ascii=False)
    except json.JSONDecodeError:
        error_json = {
            "erro": "Falha ao processar resposta do agente",
            "resposta_original": text,
            "data_da_analise": None,
            "status_de_decisao": None
        }
        return json.dumps(error_json, ensure_ascii=False)

# --- Função para busca semântica usando embeddings ---

# Inicialização do vectorstore
@st.cache_resource
def initialize_vectorstore():
    try:
        import os
        from langchain_aws import BedrockEmbeddings
        from langchain_community.vectorstores import FAISS

        embeddings = BedrockEmbeddings(
            model_id="amazon.titan-embed-text-v2:0",
            client=get_bedrock_client()
        )

        vs_dir = "vectorstore_faiss"

        if os.path.isdir(vs_dir):
            vectorstore = FAISS.load_local(
                vs_dir,
                embeddings,
                allow_dangerous_deserialization=True
            )
            return vectorstore
        else:
            st.warning(f"Vectorstore FAISS não encontrado em '{vs_dir}'. Gere-o antes de usar.")
            return None
    except Exception as e:
        st.error(f"Erro ao inicializar vectorstore (FAISS): {e}")
        return None

# busca para obter a descrição da persona
def get_persona_description_semantic(persona: str) -> str:
    if not persona:
        return "Descrição indisponível"

    try:
        vectorstore = initialize_vectorstore()
        if vectorstore is None:
            return "Descrição indisponível"

        retriever = vectorstore.as_retriever(search_kwargs={"k": 1})
        docs = retriever.invoke(persona)

        if docs and len(docs) > 0:
            return docs[0].page_content
        else:
            return "Descrição não encontrada"
    except Exception:
        return "Descrição indisponível"


# Resume cada json individual usando os 3 agentes
@st.cache_data(show_spinner=False)
def summarize_documents_combined(name: str):
    # Busca todos os documentos
    items = fetch_all_by_name(name)
    summaries = [] # Para armazenar os resumos dos documentos POD
    external_jsons = []  # Para armazenar JSONs dos documentos externos
    
    for item in items:
        json_str = json.dumps(item, ensure_ascii=False, default=str, indent=2)
        
        # Determina qual agente usar baseado no tipo de documento
        first_key = next(iter(item), None)
        if first_key == "decision":
            # Usa Agente 1 para documentos POD
            summary_json_str = agente_1_resumo_pod(json_str)
            try:
                summary_json = json.loads(summary_json_str)
                summaries.append({
                    "id": item["id"],
                    "summary": summary_json_str,  # String JSON para exibição
                    "json_data": summary_json,    # Objeto JSON para processamento
                    "type": "POD"
                })
            except json.JSONDecodeError:
                summaries.append({
                    "id": item["id"],
                    "summary": summary_json_str,
                    "type": "POD"
                })
        else:
            # Usa Agente 2 para documentos externos
            summary_json_str = agente_2_resumo_externo(json_str)
            try:
                summary_json = json.loads(summary_json_str)
                summaries.append({
                    "id": item["id"],
                    "summary": summary_json_str,  # String JSON para exibição
                    "json_data": summary_json,    # Objeto JSON para processamento
                    "type": "Externo"
                })
                external_jsons.append(summary_json)
            except json.JSONDecodeError:
                summaries.append({
                    "id": item["id"],
                    "summary": summary_json_str,
                    "type": "Externo"
                })
    
    return summaries, external_jsons

# Agente 3: Chat com contexto completo
def agente_3_chat_with_memory(system_prompt: str, user_query: list) -> str:
    client = get_bedrock_client()
    
    # Converte o histórico para o formato esperado pelo Bedrock
    messages = []
    for msg in user_query:
        messages.append({
            "role": msg["role"],
            "content": [{"type": "text", "text": msg["content"]}]
        })
    
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "system": system_prompt,
        "messages": messages,
        "max_tokens": 4096,
        "temperature": 0.4
    })
    
    resp = client.invoke_model(
        modelId=MODEL_HAIKU,
        body=body,
        contentType="application/json",
        accept="application/json"
    )
    
    data = json.loads(resp["body"].read())
    return data["content"][0]["text"].strip()

# Agente 3: Resumo automático usando os resumos dos agentes 1 e 2
def agente_3_resumo_automatico(name: str, pod_summaries: list, external_summaries: list, persona_desc: str = "") -> str:
    pod_resumos = []
    external_resumos = []
    
    for summary in pod_summaries:
        if summary.get("type") == "POD" and "json_data" in summary:
            # Cria um novo objeto com o ID e o conteúdo do resumo
            summary_with_id = {
                "document_id": summary.get("id"),
                "summary_content": summary.get("json_data")
            }
            pod_resumos.append(summary_with_id)
    
    for summary in external_summaries:
        if summary.get("type") == "Externo" and "json_data" in summary:
            summary_with_id = {
                "document_id": summary.get("id"),
                "summary_content": summary.get("json_data")
            }
            external_resumos.append(summary_with_id)
    
    # Converte para JSON strings para o prompt
    pod_json_str = json.dumps(pod_resumos, ensure_ascii=False, indent=2)
    external_json_str = json.dumps(external_resumos, ensure_ascii=False, indent=2)

    descricoes = f"""
<MENSAGEMSCORE>    Legenda: 
RISCO MUITO ALTO   De 0 a 150 
RISCO ALTO     151 a 300 
RISCO MÉDIO     301 a 500 
RISCO BAIXO     501 a 700 
RISCO MUITO BAIXO   701 a 1000 

<PERSONADIGITAL>  LEGENDA: 
Digital --   Sem propensão à canais digitais. 
Digital -     Propensão baixa à canais digitais 
Digital +-   Não é possível classificar propensão. 
Digital +    Propensão alta a canais digitais 
Digital ++   Propensão muito alta à canais digitais

<PERSONACREDITO> 
O BEM AMADO
O público mais assediado pelas empresas devido ao seu histórico de crédito impecável

SEMPRE PRESENTE
O público que é bom, porém vulnerável às interpretações de crédito do mercado

QUEM SOU EU
Pessoas sem histórico de crédito, que possuem somente histórico demográfico

PAGO QUANDO PUDER
Pessoas cujo histórico de crédito denunciam uma instabilidade no cumprimento de suas obrigações

FUJAM DE MIM
Pessoas que possuem o pior histórico de crédito devido aos inúmeros compromissos em atraso sem pagamento

NOVOS ENTRANTES
CPFs novos, jovens que não possuem histórico de crédito ou adultos que estão tirando cpf e regularizando sua situação

<PERSONADEMOGRAFICA>
{persona_desc}
"""

    system_prompt = f"""
CONTEXTO: Você é um analista de crédito e tem estes documentos internos mais recentes para o cliente {name}:

RESUMOS INTERNOS:

{pod_json_str}

e esse é o documento externo que será usado como complemento:

{external_json_str}

OBJETIVO: 
1. Listar as variáveis do campo "features" e o caminho de decisão do campo "decision_path" somente do documento interno com a data mais recente 
2. Resumir o histórico completo de crédito do cliente

INTRUÇÕES:
1. Liste todas as variáveis na ordem em que aparecem do campo "features" do documento interno com a data mais recente.
2. Liste todas as variáveis na ordem em que aparecem do campo "decision_path" do documento interno com a data mais recente.
3. Faça um resumo consolidado do histórico completo
6. NÃO omita NENHUMA variável ou caminho de decisão mesmo que pareça irrelevante.
7. Explique o significado das personas do documento externo de forma breve sem usar bullet points com base nessas informações:
{descricoes}
8. Use os resumos externos como complemento informativo
9. Escreva qual o id do documento mais recente
10. Escreva que o campo "features" são as variáveis mais importantes
11. Escreva até 4 características adicionais que você considera importante no documento externo
"""

    user_query = """Analisando o documento interno mais com a data mais recente, liste TODAS as variáveis mais importantes e TODO o caminho de decisão listado. Além disso, inclua a decision reason. 
    Em seguida, faça um resumo consolidado do histórico completo da pessoa considerando: 
    quantas análises, resultados, mudanças de decisão, datas e quem são as pessoas vinculadas. Para as variáveis personaDemografica, personaCredito, personaDigital escreva o que o valor delas significam com base nas suas descrições."""

    client = get_bedrock_client()
    body = json.dumps({
        "anthropic_version": "bedrock-2023-05-31",
        "system": system_prompt,
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": user_query}]}
        ],
        "max_tokens": 4096,
        "temperature": 0.4
    })
    resp = client.invoke_model(
        modelId=MODEL_HAIKU,
        body=body,
        contentType="application/json",
        accept="application/json"
    )
    data = json.loads(resp["body"].read())
    return data["content"][0]["text"].strip()

# --- Streamlit UI ---
# --- Inicializa estado da sessão ---
def init_session_state():
    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False
    if "username" not in st.session_state:
        st.session_state.username = ""
    if "auth_error" not in st.session_state:
        st.session_state.auth_error = None
    if "cognito_challenge" not in st.session_state:
        st.session_state.cognito_challenge = None
    if "tokens" not in st.session_state:
        st.session_state.tokens = None
    if "person_name" not in st.session_state:
        st.session_state.person_name = ""
    if "documents" not in st.session_state:
        st.session_state.documents = []
    if "error_message" not in st.session_state:
        st.session_state.error_message = None
    if "chat_history" not in st.session_state:
        st.session_state.chat_history = []
    if "doc_summaries" not in st.session_state:
        st.session_state.doc_summaries = []
    if "chat_context" not in st.session_state:
        st.session_state.chat_context = None
    if "auto_summary" not in st.session_state:
        st.session_state.auto_summary = None
    if "external_jsons" not in st.session_state:
        st.session_state.external_jsons = []
    if "persona_desc" not in st.session_state:
        st.session_state.persona_desc = ""

def display_login_page():
    st.title("🔐 Login - POD Credit Analysis")
    st.markdown("Por favor, insira suas credenciais para continuar.")

    # Se há desafio pendente (1º login), mostra o formulário de NOVA SENHA
    if st.session_state.cognito_challenge and st.session_state.cognito_challenge.get("type") == "NEW_PASSWORD_REQUIRED":
        with st.form(key="new_password_form"):
            st.info(f"Defina uma nova senha para concluir o primeiro login de **{st.session_state.cognito_challenge['username']}**.")
            new_pw  = st.text_input("Nova senha", type="password")
            new_pw2 = st.text_input("Confirmar nova senha", type="password")
            submit = st.form_submit_button("Definir nova senha e entrar")

            if submit:
                if new_pw != new_pw2:
                    st.error("As senhas não conferem.")
                else:
                    with st.spinner("Atualizando senha..."):
                        ok, err = cognito_complete_new_password(new_pw)
                        if ok:
                            st.success("Senha atualizada. Entrando...")
                            st.rerun()
                        else:
                            st.error(err)
        # Dá opção de cancelar e voltar ao login
        if st.button("Cancelar e voltar", key="cancel_new_pw"):
            st.session_state.cognito_challenge = None
            st.rerun()
        return  # não mostra o formulário de login abaixo enquanto houver desafio

    # Formulário de LOGIN normal
    with st.form(key='login_form'):
        username = st.text_input("Email", key="login_username")
        password = st.text_input("Senha", type="password", key="login_password")
        submit_button = st.form_submit_button("Login")

        if submit_button:
            with st.spinner("Autenticando..."):
                status, error = cognito_login(username, password)
                if status is True:
                    st.rerun()
                elif status == "CHALLENGE":
                    # caiu no 1º login (NEW_PASSWORD_REQUIRED)
                    st.info("Primeiro acesso detectado. Defina a nova senha abaixo.")
                    st.rerun()
                else:
                    pass

    if st.session_state.auth_error:
        st.error(st.session_state.auth_error)


def display_main_app():
    st.set_page_config(page_title="POD Credit Analysis", layout="wide") # Mova o set_page_config para cá
    st.title("🏦 POD Credit Analysis")
    

    # --- Se houver resumos individuais e nenhum chat_context, monta-o agora ---
    if st.session_state.doc_summaries and not st.session_state.chat_context:
        st.session_state.chat_context = "\n\n".join(
            f"--- Resumo {i+1} (ID: {s['id']}) ---\n{s['summary']}"
            for i, s in enumerate(st.session_state.doc_summaries)
        )

    # --- Barra lateral ---
    with st.sidebar:
        st.subheader("📑 Resumos Individuais")
        if st.session_state.doc_summaries:
            for s in st.session_state.doc_summaries:
                doc_type = s.get("type", "Desconhecido")
                if doc_type == "POD":
                    with st.expander(f"🤖 POD - ID: {s['id']}"):
                        if 'json_data' in s:
                            st.json(s['json_data'])
                        else:
                            st.markdown(s['summary'])
                elif doc_type == "Externo" and 'json_data' in s:
                    with st.expander(f"🔄 Externo - ID: {s['id']}"):
                        st.json(s['json_data'])
                else:
                    with st.expander(f"📄 ID: {s['id']}"):
                        st.markdown(s['summary'])
        else:
            st.info("Nenhum resumo gerado ainda.")
        
        # Mostra informações da persona se disponível
        if st.session_state.external_jsons:
            st.subheader("👤 Persona Demográfica")
            # Pega a persona do último documento externo
            last_external = st.session_state.external_jsons[-1] if st.session_state.external_jsons else {}
            persona = last_external.get("personaDemografica", "N/A")
            if persona != "N/A":
                st.info(f"**{persona}**")
                if st.session_state.persona_desc:
                    st.write(st.session_state.persona_desc)
            
        # Adiciona opção para limpar histórico do chat
        st.subheader("🔄 Controles")
        if st.button("Limpar Histórico do Chat", key="clear_chat"):
            st.session_state.chat_history = []
            st.rerun()

    # --- Abas principais ---
    tab1, tab2, tab3 = st.tabs([
        "Identificar Documento",
        "Conversar com Documento",
        "Resumo Automático"
    ])

    # Aba 1: busca
    with tab1:
        st.subheader("🔍 Identificar Documento")
        names = fetch_all_names()
        escolha = st.selectbox(
            "Selecione o nome:",
            options=names,
            index=names.index(st.session_state.person_name) if st.session_state.person_name in names else 0
        )
        if st.button("Buscar", key="search"):
            st.session_state.person_name   = escolha
            st.session_state.documents     = fetch_all_by_name(escolha)
            st.session_state.error_message = None
            st.session_state.chat_history  = []
            st.session_state.doc_summaries = []
            st.session_state.chat_context  = None
            st.session_state.auto_summary  = None
            st.session_state.external_jsons = []
            st.session_state.persona_desc  = ""

            if not st.session_state.documents:
                st.session_state.error_message = f"Nenhum documento para '{escolha}'."

        if st.session_state.error_message:
            st.error(st.session_state.error_message)
        elif st.session_state.documents:
            st.success(f"{len(st.session_state.documents)} documento(s) encontrados:")
            for doc in st.session_state.documents:
                with st.expander(f"Documento ID: {doc['id']}"):
                    st.json(doc)

    # --- Aba 2: conversa usando resumos pré-gerados ---
    with tab2:
        st.subheader("💬 Conversar com Documento")

        if not st.session_state.documents:
            st.info("Busque um nome na aba 1 antes de conversar.")
        else:
            if not st.session_state.doc_summaries:
                st.write("")
                
            # Criar container para o histórico de mensagens
            chat_container = st.container()
            
            # Container para o input
            input_container = st.container()
            
            # Exibir histórico de mensagens no container do chat
            with chat_container:
                for msg in st.session_state.chat_history:
                    with st.chat_message(msg["role"]):
                        st.markdown(msg["content"])
            
            # Input do usuário no container separado
            with input_container:
                user_q = st.chat_input("Pergunte algo sobre o cliente…")
                
                if user_q:
                    # Adiciona a pergunta do usuário ao histórico
                    st.session_state.chat_history.append({"role": "user", "content": user_q})
                    
                    # Se não há resumos ainda, gera usando os 3 agentes
                    if not st.session_state.doc_summaries:
                        with st.spinner("Processando documentos..."):
                            summaries, external_jsons = summarize_documents_combined(st.session_state.person_name)
                            st.session_state.doc_summaries = summaries
                            st.session_state.external_jsons = external_jsons
                            
                            # Busca semântica para persona
                            if external_jsons:
                                # Pega a persona do último documento externo
                                last_external = external_jsons[-1] if external_jsons else {}
                                persona = last_external.get("personaDemografica")
                                if persona:
                                    st.session_state.persona_desc = get_persona_description_semantic(persona)
                            
                            st.session_state.chat_context = "\n\n".join(
                                f"--- Resumo {i+1} (ID: {s['id']}) ---\n{s['summary']}"
                                for i, s in enumerate(summaries)
                            )
                    
                    # Monta o system prompt usando o chat_context com informações dos 3 agentes       
                    system_prompt = f"""
CONTEXTO: Você é um assistente de crédito especializado. Abaixo estão os resumos para {st.session_state.person_name}:

{st.session_state.chat_context if st.session_state.chat_context else "Nenhum resumo disponível ainda. Use as informações dos documentos encontrados."}

INSTRUÇÕES:
1. Responda às perguntas usando apenas as informações dos resumos acima
2. Se não souber algo, diga que não tem essa informação
3. Seja preciso e objetivo nas respostas
4. A chave do json "credit_score" é o score de crédito da pessoa 
5. A chave do json "decision_status" é o status da decisão de crédito
6. A chave do json "decision_reason" é o motivo principal da decisão de crédito
7. Não compare os id's dos documentos
8. Não diga que a semelhança entre os documentos é o nome ou documento

Importante:
- O campo "credit_score" é o score de crédito da pessoa
- Não considere documento com id sendo o nome pessoa analisada
"""
                    
                    # Chama o Agente 3 e armazena resposta
                    with st.spinner("Analisando e respondendo…"):
                        try:
                            answer = agente_3_chat_with_memory(system_prompt, st.session_state.chat_history)
                        except Exception as e:
                            answer = f"Erro ao processar a pergunta: {str(e)}"
                    
                    # Adiciona a resposta ao histórico
                    st.session_state.chat_history.append({"role": "assistant", "content": answer})
                    st.rerun()

    # --- Aba 3: gerar e mostrar resumos individuais e histórico usando os resumos dos agentes ---
    with tab3:
        st.subheader("📑 Resumo Histórico Automático")
        if not st.session_state.documents:
            st.info("Busque um nome na aba 1 antes de gerar o resumo.")
        else:
            if st.session_state.auto_summary is None:
                if st.button("Gerar Resumo Histórico", key="gen_summary"):
                    with st.spinner("Gerando resumo..."):
                        # Se não há resumos ainda, gera usando os agentes 1 e 2
                        start_time = time.time()
                        if not st.session_state.doc_summaries:
                            summaries, external_jsons = summarize_documents_combined(
                                st.session_state.person_name
                            )
                            st.session_state.doc_summaries   = summaries
                            st.session_state.external_jsons  = external_jsons

                            # busca semântica para persona
                            if external_jsons:
                                last_ext = external_jsons[-1]
                                persona = last_ext.get("personaDemografica")
                                if persona:
                                    st.session_state.persona_desc = \
                                        get_persona_description_semantic(persona)

                            # monta o contexto completo (para tab2)
                            ctx = "\n\n".join(
                                f"--- Resumo {i+1} (ID: {s['id']}) ---\n{s['summary']}"
                                for i, s in enumerate(summaries)
                            )
                            st.session_state.chat_context = ctx

                        # Usa o Agente 3 com os resumos processados pelos agentes 1 e 2
                        st.session_state.auto_summary = agente_3_resumo_automatico(
                            name=st.session_state.person_name,
                            pod_summaries=st.session_state.doc_summaries,
                            external_summaries=st.session_state.doc_summaries,
                            persona_desc=st.session_state.persona_desc
                        )
                        end_time = time.time()
                        duration = end_time - start_time
                        print(duration)
                        st.rerun()

            # exibe o resumo completo
            if st.session_state.auto_summary:
                safe_summary = st.session_state.auto_summary.replace("$", r"\$")
                st.markdown(safe_summary)


def main():
    # Inicializa o estado da sessão
    init_session_state()
    
    # Verifica se o usuário está autenticado
    if not st.session_state.authenticated:
        display_login_page()
    else:
        display_main_app()

if __name__ == "__main__":
    main()
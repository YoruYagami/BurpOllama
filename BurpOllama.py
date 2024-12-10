from burp import IBurpExtender, IHttpListener, IContextMenuFactory, ITab, IHttpRequestResponse
from java.awt import BorderLayout, FlowLayout, Color, Dimension
from java.awt.event import ActionListener, ActionEvent
from javax.swing import (JPanel, JLabel, JTextField, JButton, JComboBox, JCheckBox,
                         JScrollPane, JTextArea, JOptionPane, JTabbedPane, BoxLayout,
                         JSplitPane, SwingUtilities, JMenu, JMenuItem)
from javax.swing.border import EmptyBorder, TitledBorder
import threading
import json
import urlparse

from java.net import URL
from java.io import BufferedReader, InputStreamReader, DataOutputStream
from java.util import ArrayList

class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, ITab, ActionListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("BurpOllama")

        self.stdout = callbacks.getStdout()
        self.stderr = callbacks.getStderr()

        # Default Settings
        self.ollama_endpoint = "http://localhost:11434/api/generate"
        self.selected_model = ""
        self.max_prompt_size = 1024
        self.passive_analysis = True
        self.target_in_scope = False
        # Disable scanning by default
        self.scanning_active = False
        self.custom_prompt = (
            "Please analyze the following HTTP request and response for potential security vulnerabilities.\n\n"
            "=== Request ===\n{REQUEST}\n\n=== Response ===\n{RESPONSE}\n\n"
            "Provide a detailed analysis of potential vulnerabilities in a clear and concise manner. "
            "List each vulnerability with its name, description, and affected parameter if applicable."
        )
        self.use_json_format = True
        self.models = []

        # Chat-related state
        self.chat_messages = []
        self.chat_system_message = "You are a security expert who identifies vulnerabilities in HTTP traffic. Respond concisely."
        self.chat_user_input = ""

        # Advanced options for generation
        self.temperature = "0.7"
        self.max_tokens = "512"
        self.top_p = "1.0"
        self.frequency_penalty = "0.0"
        self.presence_penalty = "0.0"

        # Stats
        self.total_requests_analyzed = 0
        self.total_vulns_found = 0

        self.init_ui()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        self.log("[BurpOllama] Extension loaded successfully. Scanning is currently disabled by default.")

    def init_ui(self):
        self.main_tab = JTabbedPane()

        # ========== Configuration / Settings Panel ==========
        config_panel = JPanel()
        config_panel.setLayout(BoxLayout(config_panel, BoxLayout.Y_AXIS))
        config_panel.setBorder(EmptyBorder(10,10,10,10))

        title_label = JLabel("BurpOllama Pentesting Assistant")
        config_panel.add(title_label)

        instructions = JLabel("Use local Ollama AI models to analyze HTTP requests/responses for vulnerabilities. ")
        config_panel.add(instructions)

        endpoint_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        endpoint_panel.setBorder(TitledBorder("Ollama Endpoint"))
        endpoint_panel.add(JLabel("Endpoint:"))
        self.endpoint_field = JTextField(self.ollama_endpoint, 30)
        endpoint_panel.add(self.endpoint_field)
        config_panel.add(endpoint_panel)

        model_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        model_panel.setBorder(TitledBorder("Model Management"))
        model_panel.add(JLabel("Model:"))
        self.models_combo = JComboBox()
        model_panel.add(self.models_combo)
        load_models_btn = JButton("Load Models", actionPerformed=self.load_models)
        model_panel.add(load_models_btn)

        show_info_btn = JButton("Show Model Info", actionPerformed=self.show_model_info)
        model_panel.add(show_info_btn)

        pull_model_btn = JButton("Pull Model", actionPerformed=self.pull_model)
        model_panel.add(pull_model_btn)

        delete_model_btn = JButton("Delete Model", actionPerformed=self.delete_model)
        model_panel.add(delete_model_btn)

        config_panel.add(model_panel)

        prompt_size_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        prompt_size_panel.setBorder(TitledBorder("Prompt & Scope Settings"))
        prompt_size_panel.add(JLabel("Max prompt size:"))
        self.max_prompt_field = JTextField(str(self.max_prompt_size), 5)
        prompt_size_panel.add(self.max_prompt_field)

        self.passive_checkbox = JCheckBox("Analyze passively", self.passive_analysis)
        prompt_size_panel.add(self.passive_checkbox)

        self.json_checkbox = JCheckBox("JSON format", self.use_json_format)
        prompt_size_panel.add(self.json_checkbox)

        self.target_scope_checkbox = JCheckBox("Only target in scope", self.target_in_scope)
        prompt_size_panel.add(self.target_scope_checkbox)

        self.scan_toggle_btn = JButton("Start Scanning", actionPerformed=self.toggle_scanning)
        prompt_size_panel.add(self.scan_toggle_btn)
        config_panel.add(prompt_size_panel)

        advanced_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        advanced_panel.setBorder(TitledBorder("Advanced Generation Options"))
        advanced_panel.add(JLabel("Temperature:"))
        self.temperature_field = JTextField(self.temperature, 3)
        advanced_panel.add(self.temperature_field)

        advanced_panel.add(JLabel("Max Tokens:"))
        self.max_tokens_field = JTextField(self.max_tokens, 4)
        advanced_panel.add(self.max_tokens_field)

        advanced_panel.add(JLabel("Top_p:"))
        self.top_p_field = JTextField(self.top_p, 3)
        advanced_panel.add(self.top_p_field)

        advanced_panel.add(JLabel("Freq Penalty:"))
        self.freq_pen_field = JTextField(self.frequency_penalty, 3)
        advanced_panel.add(self.freq_pen_field)

        advanced_panel.add(JLabel("Presence Penalty:"))
        self.presence_pen_field = JTextField(self.presence_penalty, 3)
        advanced_panel.add(self.presence_pen_field)

        config_panel.add(advanced_panel)

        prompt_panel = JPanel(BorderLayout())
        prompt_panel.setBorder(TitledBorder("Custom Prompt Template"))
        prompt_panel.add(JLabel("<html>Available placeholders: {REQUEST}, {RESPONSE}, {URL}, {METHOD}, "
                                "{REQUEST_HEADERS}, {RESPONSE_HEADERS}, {REQUEST_BODY}, {RESPONSE_BODY}</html>"),
                         BorderLayout.NORTH)
        self.prompt_text_area = JTextArea(self.custom_prompt, 8, 50)
        prompt_scroll = JScrollPane(self.prompt_text_area)
        prompt_panel.add(prompt_scroll, BorderLayout.CENTER)
        config_panel.add(prompt_panel)

        stats_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        stats_panel.setBorder(TitledBorder("Statistics"))
        self.stats_label = JLabel("Requests Analyzed: 0 | Vulns Found: 0")
        stats_panel.add(self.stats_label)
        config_panel.add(stats_panel)

        save_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        save_btn = JButton("Save Settings", actionPerformed=self.save_settings)
        save_panel.add(save_btn)
        clear_output_btn = JButton("Clear Output", actionPerformed=self.clear_output)
        save_panel.add(clear_output_btn)
        config_panel.add(save_panel)

        self.output_panel = JPanel(BorderLayout())
        self.output_panel.setBorder(TitledBorder("Logs / Output"))
        self.output_area = JTextArea(15, 50)
        self.output_area.setEditable(False)
        self.output_area.setBackground(Color.BLACK)
        self.output_area.setForeground(Color.GREEN)
        scroll_output = JScrollPane(self.output_area)
        self.output_panel.add(scroll_output, BorderLayout.CENTER)

        settings_split_pane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        settings_split_pane.setTopComponent(config_panel)
        settings_split_pane.setBottomComponent(self.output_panel)
        settings_split_pane.setDividerLocation(500)

        self.main_tab.addTab("Settings", settings_split_pane)

        # ========== Chat Tab ==========
        chat_panel = JPanel(BorderLayout())
        chat_panel.setBorder(EmptyBorder(10,10,10,10))

        top_chat_panel = JPanel(FlowLayout(FlowLayout.LEFT))
        top_chat_panel.setBorder(TitledBorder("Chat System Message"))
        self.system_msg_field = JTextField(self.chat_system_message, 50)
        top_chat_panel.add(self.system_msg_field)

        reset_chat_btn = JButton("Reset Chat", actionPerformed=self.reset_chat)
        top_chat_panel.add(reset_chat_btn)
        chat_panel.add(top_chat_panel, BorderLayout.NORTH)

        chat_history_panel = JPanel(BorderLayout())
        chat_history_panel.setBorder(TitledBorder("Chat History"))
        self.chat_area = JTextArea(25, 70)  # Increased size
        self.chat_area.setEditable(False)
        self.chat_area.setLineWrap(True)
        self.chat_area.setWrapStyleWord(True)
        chat_history_panel.add(JScrollPane(self.chat_area), BorderLayout.CENTER)
        chat_panel.add(chat_history_panel, BorderLayout.CENTER)

        bottom_chat_panel = JPanel(BorderLayout())
        bottom_chat_panel.setBorder(TitledBorder("User Input"))
        self.user_input_field = JTextArea("", 5, 60)  # Changed to JTextArea for multi-line input
        self.user_input_field.setLineWrap(True)
        self.user_input_field.setWrapStyleWord(True)
        input_scroll = JScrollPane(self.user_input_field)
        send_msg_btn = JButton("Send", actionPerformed=self.send_chat_message)
        bottom_chat_panel.add(input_scroll, BorderLayout.CENTER)
        bottom_chat_panel.add(send_msg_btn, BorderLayout.EAST)
        chat_panel.add(bottom_chat_panel, BorderLayout.SOUTH)

        self.main_tab.addTab("Chat", chat_panel)

    def getTabCaption(self):
        return "BurpOllama"

    def getUiComponent(self):
        return self.main_tab

    def toggle_scanning(self, event):
        self.scanning_active = not self.scanning_active
        self.scan_toggle_btn.setText("Start Scanning" if not self.scanning_active else "Stop Scanning")
        status = "stopped" if not self.scanning_active else "started"
        self.log("Scanning " + status + ".")

    def save_settings(self, event):
        self.ollama_endpoint = self.endpoint_field.getText().strip()
        try:
            self.max_prompt_size = int(self.max_prompt_field.getText().strip())
        except ValueError:
            self.max_prompt_size = 1024  # Default value if parsing fails
            self.log("Invalid max prompt size. Using default value 1024.")
        self.passive_analysis = self.passive_checkbox.isSelected()
        self.custom_prompt = self.prompt_text_area.getText()
        self.use_json_format = self.json_checkbox.isSelected()
        if self.models_combo.getItemCount() > 0:
            self.selected_model = str(self.models_combo.getSelectedItem())
        self.chat_system_message = self.system_msg_field.getText().strip()
        self.temperature = self.temperature_field.getText().strip()
        self.max_tokens = self.max_tokens_field.getText().strip()
        self.top_p = self.top_p_field.getText().strip()
        self.frequency_penalty = self.freq_pen_field.getText().strip()
        self.presence_penalty = self.presence_pen_field.getText().strip()
        self.target_in_scope = self.target_scope_checkbox.isSelected()

        JOptionPane.showMessageDialog(self.main_tab, "Settings saved.", "Local Ollama", JOptionPane.INFORMATION_MESSAGE)
        self.log("Settings saved.")

    def clear_output(self, event):
        self.output_area.setText("")

    def load_models(self, event):
        def do_load():
            tags_endpoint = self.ollama_endpoint.replace("/api/generate","/api/tags")
            resp = self.send_get_request(tags_endpoint)
            if resp and "models" in resp:
                self.models = [m["name"] for m in resp["models"]]
                SwingUtilities.invokeLater(self.update_models_combo)
            else:
                self.log("Failed to load models.")
        t = threading.Thread(target=do_load)
        t.start()

    def update_models_combo(self):
        self.models_combo.removeAllItems()
        for model in self.models:
            self.models_combo.addItem(model)
        if self.models:
            self.selected_model = self.models[0]
        self.log("Models loaded successfully.")

    def show_model_info(self, event):
        if not self.selected_model:
            self.log("No model selected.")
            return
        def do_show():
            show_endpoint = self.ollama_endpoint.replace("/api/generate", "/api/show")
            payload = {"model": self.selected_model}
            resp = self.send_post_request(show_endpoint, payload)
            if resp:
                self.log("Model Info:\n" + json.dumps(resp, indent=2))
            else:
                self.log("Failed to retrieve model info.")
        t = threading.Thread(target=do_show)
        t.start()

    def pull_model(self, event):
        model_name = JOptionPane.showInputDialog(self.main_tab, "Enter model name to pull (e.g., llama3.2):", "Pull Model", JOptionPane.QUESTION_MESSAGE)
        if model_name:
            def do_pull():
                pull_endpoint = self.ollama_endpoint.replace("/api/generate", "/api/pull")
                payload = {"model": model_name}
                resp = self.send_post_request(pull_endpoint, payload)
                if resp:
                    self.log("Pull response:\n" + json.dumps(resp, indent=2))
                else:
                    self.log("Failed to pull model.")
            t = threading.Thread(target=do_pull)
            t.start()

    def delete_model(self, event):
        if not self.selected_model:
            self.log("No model selected.")
            return
        confirm = JOptionPane.showConfirmDialog(self.main_tab, "Are you sure you want to delete this model?", "Delete Model", JOptionPane.YES_NO_OPTION)
        if confirm == JOptionPane.YES_OPTION:
            def do_delete():
                delete_endpoint = self.ollama_endpoint.replace("/api/generate", "/api/delete")
                payload = {"model": self.selected_model}
                response_code = self.send_delete_request(delete_endpoint, payload)
                if response_code == 200:
                    self.log("Model deleted: " + self.selected_model)
                else:
                    self.log("Failed to delete model.")
            t = threading.Thread(target=do_delete)
            t.start()

    def reset_chat(self, event):
        self.chat_messages = []
        self.chat_area.setText("")
        self.log("Chat reset. New conversation started.")
        self.write_chat_line("System message reset. Start a new conversation.")

    def send_chat_message(self, event):
        user_message = self.user_input_field.getText().strip()
        if not user_message:
            return
        self.user_input_field.setText("")
        if not any(m['role'] == 'system' for m in self.chat_messages):
            self.chat_messages.append({"role": "system", "content": self.chat_system_message})
        self.chat_messages.append({"role": "user", "content": user_message})
        self.write_chat_line("You: " + user_message)
        thread = threading.Thread(target=self.send_chat_request)
        thread.start()

    def send_chat_request(self):
        if not self.selected_model:
            self.write_chat_line("No model selected.")
            return
        chat_endpoint = self.ollama_endpoint.replace("/api/generate", "/api/chat")
        payload = {
            "model": self.selected_model,
            "messages": self.chat_messages,
            "stream": False
        }
        if self.use_json_format:
            payload["format"] = "json"
        options = self.build_options()
        if options:
            payload["options"] = options

        resp = self.send_post_request(chat_endpoint, payload)
        if resp and "message" in resp:
            assistant_content = resp["message"].get("content","")
            self.chat_messages.append({"role":"assistant","content":assistant_content})
            self.write_chat_line("Assistant: " + assistant_content)
        else:
            self.write_chat_line("No response or error from model.")

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        if not self.scanning_active:
            return

        if not self.passive_analysis or messageIsRequest:
            return
        if not self.selected_model:
            return

        request_info = self._helpers.analyzeRequest(messageInfo)
        if request_info.getUrl():
            if self.target_in_scope and not self._callbacks.isInScope(request_info.getUrl()):
                return  # Not in scope

        url = ""
        host = ""
        endpoint = ""
        param_name = ""

        if request_info.getUrl():
            url = request_info.getUrl().toString()
            parsed = self.parse_url(url)
            host = parsed["host"]
            endpoint = parsed["path"]
            if parsed["params"]:
                param_name = list(parsed["params"].keys())[0]

        request_str = self._helpers.bytesToString(messageInfo.getRequest())
        response_str = ""
        if messageInfo.getResponse():
            response_str = self._helpers.bytesToString(messageInfo.getResponse())

        method = request_info.getMethod()
        request_headers = request_info.getHeaders()
        request_body = request_str[self._helpers.analyzeRequest(messageInfo).getBodyOffset():]

        response_headers = []
        response_body = ""
        if messageInfo.getResponse():
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            response_headers = response_info.getHeaders()
            response_body = response_str[self._helpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset():]

        prompt = self.build_prompt(request_str, url, method, request_headers, request_body,
                                   response_str, response_headers, response_body)

        self.total_requests_analyzed += 1
        self.update_stats()

        thread = threading.Thread(target=self.send_to_ollama_for_request, args=(prompt, messageInfo, host, endpoint, param_name, request_str, response_str))
        thread.start()

    def send_to_ollama_for_request(self, prompt, messageInfo, host, endpoint, param_name, request_str="", response_str=""):
        if not self.selected_model:
            return
        payload = {
            "model": self.selected_model,
            "prompt": prompt,
            "stream": False
        }
        if self.use_json_format:
            payload["format"] = "json"
        options = self.build_options()
        if options:
            payload["options"] = options

        resp = self.send_post_request(self.ollama_endpoint, payload)
        if resp:
            analysis = resp.get("response", "")
            self.handle_analysis(analysis, messageInfo, host, endpoint, param_name, request_str, response_str)

    def handle_analysis_chat(self, analysis, messageInfo, host, endpoint, param_name, request_str, response_str):
        # Attempt to parse analysis as JSON
        try:
            parsed = json.loads(analysis)
            vulnerabilities = parsed.get("vulnerabilities", [])
            
            if vulnerabilities:
                formatted_vulns = ""
                for idx, vuln in enumerate(vulnerabilities, 1):
                    name = vuln.get("name", "Unnamed Vulnerability")
                    desc = vuln.get("description", "No description provided.")
                    parameter = vuln.get("parameter", "N/A")
                    formatted_vulns += "{0}. **{1}**\n   - **Description:** {2}\n   - **Parameter:** {3}\n\n".format(idx, name, desc, parameter)
                
                response_text = "**Potential Vulnerabilities Identified:**\n\n" + formatted_vulns
            else:
                response_text = "No significant vulnerabilities were identified."
            
        except ValueError:
            # If not JSON, treat the response as plain text
            response_text = analysis

        # Send the formatted analysis back as the assistant's message
        self.chat_messages.append({"role": "assistant", "content": response_text})
        self.write_chat_line("Assistant: " + response_text)

        if vulnerabilities:
            if messageInfo:
                messageInfo.setComment("BurpOllama identified potential issues:\n" + analysis)
                messageInfo.setHighlight("red")
            self.total_vulns_found += len(vulnerabilities)
            self.update_stats()

        # Optionally, log the analysis
        self.write_output("Analysis:\n" + response_text + "\n")

    def handle_analysis(self, analysis, messageInfo, host, endpoint, param_name, request_str, response_str):
        # This method handles analysis for automatic scanning
        self.handle_analysis_chat(analysis, messageInfo, host, endpoint, param_name, request_str, response_str)

    def build_prompt(self, request_str, url, method, request_headers, request_body,
                     response_str, response_headers, response_body):
        prompt = self.custom_prompt
        prompt = prompt.replace("{REQUEST}", request_str)
        prompt = prompt.replace("{URL}", url)
        prompt = prompt.replace("{METHOD}", method)
        prompt = prompt.replace("{REQUEST_HEADERS}", "\n".join(request_headers))
        prompt = prompt.replace("{REQUEST_BODY}", request_body)
        prompt = prompt.replace("{RESPONSE}", response_str)
        prompt = prompt.replace("{RESPONSE_HEADERS}", "\n".join(response_headers))
        prompt = prompt.replace("{RESPONSE_BODY}", response_body)

        truncated = False
        if len(prompt) > self.max_prompt_size:
            prompt = prompt[:self.max_prompt_size]
            truncated = True
        prompt = prompt.replace("{IS_TRUNCATED_PROMPT}", str(truncated).lower())
        return prompt

    def build_options(self):
        def parse_float(val, default):
            try:
                return float(val)
            except:
                return default
        def parse_int(val, default):
            try:
                return int(val)
            except:
                return default
        temp_val = parse_float(self.temperature,0.7)
        max_t = parse_int(self.max_tokens,512)
        top_p = parse_float(self.top_p,1.0)
        freq_p = parse_float(self.frequency_penalty,0.0)
        pres_p = parse_float(self.presence_penalty,0.0)

        options = {
            "temperature": temp_val,
            "top_p": top_p,
            "frequency_penalty": freq_p,
            "presence_penalty": pres_p,
            "num_predict": max_t
        }
        return options

    def write_chat_line(self, line):
        def append_line():
            try:
                self.chat_area.append(line + "\n")
                # Auto-scroll to the bottom
                self.chat_area.setCaretPosition(self.chat_area.getDocument().getLength())
                self.log("Appended to chat: " + line)
            except Exception as e:
                self.log("Error appending to chat: " + str(e))
        if SwingUtilities.isEventDispatchThread():
            append_line()
        else:
            SwingUtilities.invokeLater(append_line)

    def send_post_request(self, endpoint, payload):
        try:
            url = URL(endpoint)
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestMethod("POST")
            connection.setRequestProperty("Content-Type", "application/json")

            data = json.dumps(payload)
            output_stream = DataOutputStream(connection.getOutputStream())
            output_stream.writeBytes(data)
            output_stream.flush()
            output_stream.close()

            response_code = connection.getResponseCode()
            if response_code == 200:
                input_stream = connection.getInputStream()
                reader = BufferedReader(InputStreamReader(input_stream))
                response = []
                line = reader.readLine()
                while line:
                    response.append(line)
                    line = reader.readLine()
                reader.close()
                return json.loads("".join(response))
            else:
                self.log("POST Error: HTTP " + str(response_code))
                return None
        except Exception as e:
            self.log("Exception in POST: " + str(e))
            return None

    def send_delete_request(self, endpoint, payload):
        try:
            url = URL(endpoint)
            connection = url.openConnection()
            connection.setDoOutput(True)
            connection.setRequestMethod("DELETE")
            connection.setRequestProperty("Content-Type", "application/json")

            data = json.dumps(payload)
            output_stream = DataOutputStream(connection.getOutputStream())
            output_stream.writeBytes(data)
            output_stream.flush()
            output_stream.close()

            response_code = connection.getResponseCode()
            return response_code
        except Exception as e:
            self.log("Exception in DELETE: " + str(e))
            return None

    def send_get_request(self, endpoint):
        try:
            url = URL(endpoint)
            connection = url.openConnection()
            connection.setRequestMethod("GET")
            connection.setRequestProperty("Content-Type", "application/json")
            connection.connect()

            response_code = connection.getResponseCode()
            if response_code == 200:
                input_stream = connection.getInputStream()
                reader = BufferedReader(InputStreamReader(input_stream))
                response = []
                line = reader.readLine()
                while line:
                    response.append(line)
                    line = reader.readLine()
                reader.close()
                return json.loads("".join(response))
            else:
                self.log("GET Error: HTTP " + str(response_code))
                return None
        except Exception as e:
            self.log("Exception in GET: " + str(e))
            return None

    def write_output(self, text):
        def append_text():
            self.output_area.append(text)
        if SwingUtilities.isEventDispatchThread():
            append_text()
        else:
            SwingUtilities.invokeLater(append_text)

    def log(self, msg):
        self.stdout.write(msg+"\n")
        self.stdout.flush()
        self.write_output(msg+"\n")

    def actionPerformed(self, event):
        pass

    def createMenuItems(self, invocation):
        menu = ArrayList()
        # Create a submenu "Send to BurpOllama"
        submenu = JMenu("Send to BurpOllama")
        # Add an item "Send to Ollama" under it
        send_item = JMenuItem("Send to Ollama", actionPerformed=lambda e: self.manual_analyze(invocation))
        submenu.add(send_item)
        # Add separate menu items for sending Request or Response
        send_request_item = JMenuItem("Send Request to Ollama", actionPerformed=lambda e: self.send_to_chat(invocation, "request"))
        submenu.add(send_request_item)
        send_response_item = JMenuItem("Send Response to Ollama", actionPerformed=lambda e: self.send_to_chat(invocation, "response"))
        submenu.add(send_response_item)
        menu.add(submenu)
        return menu

    def manual_analyze(self, invocation):
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages:
            self.log("No message selected for analysis.")
            return
        messageInfo = selected_messages[0]
        request_info = self._helpers.analyzeRequest(messageInfo)
        request_str = self._helpers.bytesToString(messageInfo.getRequest())
        response_str = ""
        if messageInfo.getResponse():
            response_str = self._helpers.bytesToString(messageInfo.getResponse())

        url = ""
        host = ""
        endpoint = ""
        param_name = ""
        if request_info.getUrl():
            url = request_info.getUrl().toString()
            parsed = self.parse_url(url)
            host = parsed["host"]
            endpoint = parsed["path"]
            if parsed["params"]:
                param_name = list(parsed["params"].keys())[0]

        method = request_info.getMethod()
        request_headers = request_info.getHeaders()
        request_body = request_str[self._helpers.analyzeRequest(messageInfo).getBodyOffset():]

        response_headers = []
        response_body = ""
        if messageInfo.getResponse():
            response_info = self._helpers.analyzeResponse(messageInfo.getResponse())
            response_headers = response_info.getHeaders()
            response_body = response_str[self._helpers.analyzeResponse(messageInfo.getResponse()).getBodyOffset():]

        prompt = self.build_prompt(request_str, url, method, request_headers, request_body,
                                   response_str, response_headers, response_body)

        self.total_requests_analyzed += 1
        self.update_stats()

        thread = threading.Thread(target=self.send_to_ollama_for_request, args=(prompt, messageInfo, host, endpoint, param_name, request_str, response_str))
        thread.start()

    def send_to_chat(self, invocation, part):
        selected_messages = invocation.getSelectedMessages()
        if not selected_messages:
            self.log("No message selected to send to chat.")
            return
        messageInfo = selected_messages[0]
        request_info = self._helpers.analyzeRequest(messageInfo)
        request_str = self._helpers.bytesToString(messageInfo.getRequest())
        response_str = ""
        if messageInfo.getResponse():
            response_str = self._helpers.bytesToString(messageInfo.getResponse())

        if part == "request":
            content = "**Request:**\n{}".format(request_str)
        elif part == "response":
            if not response_str:
                self.log("No response available to send.")
                return
            content = "**Response:**\n{}".format(response_str)
        else:
            self.log("Invalid part specified to send to chat.")
            return

        # Send the content as a user message to the chat
        self.chat_messages.append({"role": "user", "content": content})
        self.write_chat_line("You: " + content)
        self.write_output("Sent to chat: {}\n".format(content))

        # Trigger the model to analyze
        thread = threading.Thread(target=self.send_chat_request)
        thread.start()

    def handle_analysis_chat(self, analysis, messageInfo, host, endpoint, param_name, request_str, response_str):
        # Attempt to parse analysis as JSON
        try:
            parsed = json.loads(analysis)
            vulnerabilities = parsed.get("vulnerabilities", [])
            
            if vulnerabilities:
                formatted_vulns = ""
                for idx, vuln in enumerate(vulnerabilities, 1):
                    name = vuln.get("name", "Unnamed Vulnerability")
                    desc = vuln.get("description", "No description provided.")
                    parameter = vuln.get("parameter", "N/A")
                    formatted_vulns += "{0}. **{1}**\n   - **Description:** {2}\n   - **Parameter:** {3}\n\n".format(idx, name, desc, parameter)
                
                response_text = "**Potential Vulnerabilities Identified:**\n\n" + formatted_vulns
            else:
                response_text = "No significant vulnerabilities were identified."
            
        except ValueError:
            # If not JSON, treat the response as plain text
            response_text = analysis

        # Send the formatted analysis back as the assistant's message
        self.chat_messages.append({"role": "assistant", "content": response_text})
        self.write_chat_line("Assistant: " + response_text)

        if vulnerabilities:
            if messageInfo:
                messageInfo.setComment("BurpOllama identified potential issues:\n" + analysis)
                messageInfo.setHighlight("red")
            self.total_vulns_found += len(vulnerabilities)
            self.update_stats()

        # Optionally, log the analysis
        self.write_output("Analysis:\n" + response_text + "\n")

    def handle_analysis(self, analysis, messageInfo, host, endpoint, param_name, request_str, response_str):
        # This method handles analysis for automatic scanning
        self.handle_analysis_chat(analysis, messageInfo, host, endpoint, param_name, request_str, response_str)

    def send_chat_request(self):
        if not self.selected_model:
            self.write_chat_line("No model selected.")
            return
        chat_endpoint = self.ollama_endpoint.replace("/api/generate", "/api/chat")
        payload = {
            "model": self.selected_model,
            "messages": self.chat_messages,
            "stream": False
        }
        if self.use_json_format:
            payload["format"] = "json"
        options = self.build_options()
        if options:
            payload["options"] = options

        resp = self.send_post_request(chat_endpoint, payload)
        if resp and "message" in resp:
            assistant_content = resp["message"].get("content","")
            self.chat_messages.append({"role":"assistant","content":assistant_content})
            self.write_chat_line("Assistant: " + assistant_content)
        else:
            self.write_chat_line("No response or error from model.")

    def parse_url(self, url_str):
        try:
            parsed = urlparse.urlparse(url_str)
            qs = urlparse.parse_qs(parsed.query)
            return {
                "host": parsed.netloc,
                "path": parsed.path,
                "params": qs
            }
        except:
            return {"host":"", "path":"", "params":{}}

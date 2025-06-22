# hunterNG/modules/assessment/assessment_module.py

import os
import re
from pathlib import Path
from typing import Any, Dict, List
from modules.base_module import BaseModule
from autogen import LLMConfig
from autogen.agentchat import ConversableAgent
from autogen.agentchat import initiate_group_chat
from autogen.agentchat.group.patterns import AutoPattern

class AssessmentModule(BaseModule):
    def __init__(self, module_name: str, 
                 target: str, 
                 output_dir: Path, 
                 global_state: Dict[str, Any], 
                 verbose: bool = False):
        super().__init__(module_name, target, output_dir, global_state, verbose)
        
        # Define vulnerability categories for organizing results
        self.vulnerability_categories = {
            'sqli': ['sqli', 'sql-injection', 'mysql', 'postgresql', 'oracle', 'mssql'],
            'xss': ['xss', 'cross-site-scripting', 'reflected-xss', 'stored-xss', 'dom-xss'],
            'cmdi': ['cmdi', 'command-injection', 'code-injection', 'rce'],
            'crlf': ['crlf', 'crlf-injection'],
            'injection': ['injection', 'csv-injection', 'xinclude-injection'],
            'lfi': ['lfi', 'local-file-inclusion', 'path-traversal'],
            'redirect': ['redirect', 'open-redirect'],
            'rfi': ['rfi', 'remote-file-inclusion'],
            'ssrf': ['ssrf', 'server-side-request-forgery'],
            'ssti': ['ssti', 'server-side-template-injection', 'template-injection'],
            'xxe': ['xxe', 'xml-external-entity'],
            'cve': ['cve-']
        }

    def run(self, **kwargs) -> Dict[str, Any]:
        super().run(**kwargs)
        
        target_info = self.global_state.get('target_info', {})
        target_type = target_info.get('target_type', 'domain')

        results: Dict[str, Any] = {
            "target": self.target,
            "module_name": self.module_name,
            "output_dir": str(self.module_output_dir),
            "target_type": target_type,
        }

        llm_mini = LLMConfig(
            api_type="openai",
            api_key=os.getenv("OPENAI_API_KEY"),
            model="gpt-4.1-mini",
            temperature=0.1,
        )

        llm_nano = LLMConfig(
            api_type="openai",
            api_key=os.getenv("OPENAI_API_KEY"),
            model="gpt-4.1-nano",
            temperature=0.1,
        )

        def save_llm_candidates(llm_candidates: str):
            """
            Saves a string containing multiple newline-separated URLs
            into the llm_candidates.txt file.
            """
            self._save_task_results(llm_candidates, "llm_candidates")

        def is_termination_msg(x: dict[str, Any]) -> bool:
            content = x.get("content", "")
            return (content is not None) and "==== CANDIDATES GENERATED ====" in content

        self.console.print(f"[blue]Running LLM[/blue]")

        find_candidates_agent = ConversableAgent(
            name="FindCandidatesAgent",
            system_message="""
            You are an expert security assessment agent.
            Your task is to select top 10 URLs from a given list of URLs that are most likely to be vulnerable.
            Prioritize URLs with:
            - multiple parameters,
            - suspicious or sensitive parameter names (like id, user, token, pass, admin, redirect, file...),
            - unusual or deeply nested paths,
            - parameters with empty or generic values,
            - or anything else that looks interesting for a pentest.
            Output a list of 10 URLs, each on a new line, and **do not** include any explanation or extra text.
            """,
            llm_config=llm_mini,
        )

        save_candidates_agent = ConversableAgent(
            name="SaveCandidatesAgent",
            system_message="""
            You are a file saving agent.
            Your task is to save a list of URLs to a file named candidates.txt in the specified output directory.
            The input will be a string containing the URLs, each on a new line.

            Once you save the URLs, return the below message:
            ==== CANDIDATES GENERATED ====
            """,
            llm_config=llm_nano,
            functions=[save_llm_candidates]
        )

        initial_prompt = self._load_task_results("url_param", source_module_name="recon")

        pattern = AutoPattern(
            initial_agent=find_candidates_agent,
            agents=[find_candidates_agent, save_candidates_agent],
            group_manager_args={
                "llm_config": llm_mini,
                "is_termination_msg": is_termination_msg
            }
        )

        result, context_variables, last_agent = initiate_group_chat(
            pattern=pattern,
            messages=initial_prompt,
        )

        # Nuclei
        self.console.print(f"[blue]Running Nulclei[/blue]")
        input_url = self._get_urls_for_scanning()
        all_findings = self._scan_urls_individually(input_url)
        if all_findings:
            self._save_task_results("\n".join(all_findings), "nuclei")
            # Categorize and save vulnerability candidates by type
            self._categorize_and_save_vulnerabilities(all_findings)
            self.console.print(f"[green]Vulnerability scanning completed: {len(all_findings)} total findings[/green]")
        else:
            self.console.print(f"[green]Vulnerability scanning completed: No vulnerabilities found[/green]")
            self._save_task_results("", "nuclei")

        # Dalfox
        self.console.print(f"[blue]Running Dalfox XSS[/blue]")
        input_for_dalfox = self._get_input_for_dalfox()
        if input_for_dalfox:
            dalfox_results = self._execute_command_task("dalfox", stdin_data="\n".join(input_for_dalfox))
            if dalfox_results.success and dalfox_results.stdout:
                clean_output = self._remove_ansi_escapes(dalfox_results.stdout)
                self._save_task_results(clean_output, "dalfox_xss_candidates")
            else:
                self.console.print("[yellow]Dalfox XSS scanning did not find any candidates[/yellow]")
                self._save_task_results("", "dalfox_xss_candidates")
        else:
            self.console.print("[yellow]No URLs available for Dalfox XSS scanning[/yellow]")
            self._save_task_results("", "dalfox_xss_candidates")

        self._save_module_results(results)
        return results

    def _get_urls_for_scanning(self) -> List[str]:
        urls = []
        param_urls = self._load_task_results("llm_candidates")
        if param_urls and param_urls.strip():
            urls.extend([url.strip() for url in param_urls.strip().splitlines() if url.strip()])
        # If no parameterized URLs, get live hosts
        if not urls:
            live_hosts = self._load_task_results("url_param", source_module_name="recon")
            if live_hosts and live_hosts.strip():
                urls.extend([url.strip() for url in live_hosts.strip().splitlines() if url.strip()])
        if not urls:
            live_hosts = self._load_task_results("live_hosts", source_module_name="recon")
            if live_hosts and live_hosts.strip():
                urls.extend([url.strip() for url in live_hosts.strip().splitlines() if url.strip()])
        # If still no URLs, use the primary target
        if not urls:
            urls.append(self._get_primary_scan_target())
        
        return urls

    def _scan_urls_individually(self, urls: List[str]) -> List[str]:
        all_findings = []
        
        for i, url in enumerate(urls, 1):
            self.console.print(f"[dim]Scanning URL {i}/{len(urls)}: {url}[/dim]")
            result = self._execute_command_task("nuclei", stdin_data=url)
            
            if result.success and result.stdout:
                findings = self._extract_clean_findings(result.stdout)
                if findings:
                    all_findings.extend(findings)
                    # Show quick summary of what was found
                    found_types = self._get_vuln_types_from_findings(findings)
                    types_str = ", ".join(found_types) if found_types else "unknown"
                    self.console.print(f"[green]Found {len(findings)} vulnerabilities: {types_str}[/green]")
        
        return all_findings

    
    def _extract_clean_findings(self, nuclei_output: str) -> List[str]:
        findings = []
        lines = nuclei_output.strip().splitlines()
        
        # Remove ANSI escape sequences
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        sql_error_pattern = re.compile(r'\s\[".*?"\]')
        
        for line in lines:
            clean_line = ansi_escape.sub('', line).strip()
            clean_line = sql_error_pattern.sub('', clean_line)
            if re.match(r'^\[.*\] \[.*\] \[.*\] http', clean_line):
                findings.append(clean_line)
                
        return findings

    def _get_vuln_types_from_findings(self, findings: List[str]) -> List[str]:
        found_types = set()
        
        for finding in findings:
            template_match = re.match(r'^\[([^\]]+)\]', finding)
            if template_match:
                template_name = template_match.group(1).lower()
                
                for category, keywords in self.vulnerability_categories.items():
                    if any(keyword in template_name for keyword in keywords):
                        found_types.add(category)
                        break
        
        return sorted(list(found_types))

    def _categorize_and_save_vulnerabilities(self, findings: List[str]) -> None:
        categorized = {}
        
        for category in self.vulnerability_categories.keys():
            categorized[category] = []
        
        # Categorize each finding
        for finding in findings:
            template_match = re.match(r'^\[([^\]]+)\]', finding)
            if template_match:
                template_name = template_match.group(1).lower()
                
                # Find matching category
                for category, keywords in self.vulnerability_categories.items():
                    if any(keyword in template_name for keyword in keywords):
                        categorized[category].append(finding)
                        break

        for category, vulns in categorized.items():
            if vulns:
                self._save_task_results("\n".join(vulns), f"{category}_candidates")

    def _get_input_for_dalfox(self) -> List[str]:
        urls_for_dalfox = set()

        # Ưu tiên 1: Nếu không có, lấy từ ứng viên do LLM chọn
        if not urls_for_dalfox:
            llm_candidates = self._load_task_results("llm_candidates")
            if llm_candidates and llm_candidates.strip():
                urls_for_dalfox.update([url.strip() for url in llm_candidates.strip().splitlines() if url.strip()])

        # Ưu tiên 2: Lấy URL từ kết quả XSS của Nuclei
        if not urls_for_dalfox:
            xss_candidates_content = self._load_task_results("xss_candidates")
            if xss_candidates_content and xss_candidates_content.strip():
                url_pattern = re.compile(r'https?://[^\s]+')
                for line in xss_candidates_content.strip().splitlines():
                    if not line.strip():
                        continue
                    match = url_pattern.search(line)
                    if match:
                        raw_url = match.group(0)
                        cleaned_url = raw_url.split("'", 1)[0]
                        urls_for_dalfox.add(cleaned_url)

        if urls_for_dalfox:
            sorted_urls = sorted(list(urls_for_dalfox))
            self._save_task_results("\n".join(sorted_urls), "input_for_dalfox")
            return sorted_urls
        else:
            self._save_task_results("", "input_for_dalfox")
            return []
        
    def _remove_ansi_escapes(self, text: str) -> str:
        """Removes ANSI escape sequences from a string."""
        if not text:
            return ""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
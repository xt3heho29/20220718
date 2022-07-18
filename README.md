# 20220718
F5 BIG-IP iControl REST Vulnerability CVE-2022-1388
| tstats count from datamodel=Web where Web.url="*/mgmt/tm/util/bash*" Web.http_method="POST" by Web.http_user_agent Web.http_method, Web.url,Web.url_length Web.src, Web.dest 
| `drop_dm_object_name("Web")`

Web Spring Cloud Function FunctionRouter
| tstats count from datamodel=Web where Web.http_method IN ("POST") Web.url="*/functionRouter*" by Web.http_user_agent Web.http_method, Web.url,Web.url_length Web.src, Web.dest Web.status sourcetype 
| `drop_dm_object_name("Web")` 

Web Spring4Shell HTTP Request Class Module
`stream_http` http_method IN ("POST") 
| stats values(form_data) as http_request_body min(_time) as firstTime max(_time) as lastTime count by http_method http_user_agent uri_path url bytes_in bytes_out 
| search http_request_body IN ("*class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=_*", "*class.module.classLoader.resources.context.parent.pipeline.first.pattern*","*suffix=.jsp*") 

Web JSP Request via URL
| tstats count from datamodel=Web where Web.http_method IN ("GET") Web.url IN ("*.jsp?cmd=*","*j&cmd=*") by Web.http_user_agent Web.http_method, Web.url,Web.url_length Web.src, Web.dest sourcetype 
| `drop_dm_object_name("Web")` 

Spring4Shell Payload URL Request
| tstats count from datamodel=Web where Web.http_method IN ("GET") Web.url IN ("*tomcatwar.jsp*","*poc.jsp*","*shell.jsp*") by Web.http_user_agent Web.http_method, Web.url,Web.url_length Web.src, Web.dest sourcetype 
| `drop_dm_object_name("Web")` 

Outbound Network Connection from Java Using Default Ports
| tstats count FROM datamodel=Endpoint.Processes where (Processes.process_name="java.exe" OR Processes.process_name=javaw.exe OR Processes.process_name=javaw.exe) by _time Processes.process_id Processes.process_name Processes.dest Processes.process_path Processes.process Processes.parent_process_name 
| `drop_dm_object_name(Processes)`
| join process_id [
| tstats `security_content_summariesonly` count FROM datamodel=Network_Traffic.All_Traffic where (All_Traffic.dest_port= 389 OR All_Traffic.dest_port= 636 OR All_Traffic.dest_port = 1389 OR All_Traffic.dest_port = 1099 ) by All_Traffic.process_id All_Traffic.dest All_Traffic.dest_port 
| `drop_dm_object_name(All_Traffic)` 
| rename dest as connection_to_CNC] 
| table _time dest parent_process_name process_name process_path process connection_to_CNC dest_port


from pydantic import BaseModel, Field

from .action_base import JIRAAction
from .base import JIRAModule


class JiraCreateIssueArguments(BaseModel):
    project_key: str = Field(..., description="Project key (e.g. 'PRJ')")
    summary: str = Field(..., description="Summary of an issue (e.g. 'Fix a bug')")
    issue_type: str = Field(..., description="Issue type (e.g. 'Task')")
    due_date: str | None = Field(description="Due date (e.g. '2023-10-31')'")
    labels: str | None = Field(description="Comma-separated labels (e.g. 'devops,support')")
    assignee: str | None = Field(description="Exact display name of an assignee (e.g. John Doe)")
    reporter: str | None = Field(description="Exact display name of a reporter (e.g. Jane Doe)")
    priority: str | None = Field(description="Issue priority (e.g. Highest)")
    parent_key: str | None = Field(None, description="Key of a parent issue (e.g. PRJ-1)")


class JIRACreateIssue(JIRAAction):
    name = "Create an issue"
    description = "Create an issue"
    module: JIRAModule

    def get_create_issue_meta(self, project_key: str, issue_type: str) -> dict | None:
        response: dict = self.get_json(
            "issue/createmeta",
            params={"projectKeys": project_key, "issuetypeNames": issue_type},
        )

        projects = response.get("projects")
        if not projects or len(projects) == 0:
            self.log(message="Project `%s` is not found" % project_key, level="error")
            return None

        project = projects[0]
        project_id = project.get("id")
        issues_types = project.get("issuetypes")

        if not issues_types or len(issues_types) == 0:
            self.log(message="Issue type `%s` is not found " % issue_type, level="error")
            return None

        issue_type_id = project["issuetypes"][0]["id"]
        return {"project_id": project_id, "issue_type_id": issue_type_id}

    def run(self, arguments: JiraCreateIssueArguments) -> dict | None:
        meta = self.get_create_issue_meta(project_key=arguments.project_key, issue_type=arguments.issue_type)
        if not meta:
            self.log("Project key OR/AND issue type are incorrect", level="error")
            return None

        # Mandatory Fields
        params = {
            "project": {"id": meta["project_id"]},
            "issuetype": {"id": meta["issue_type_id"]},
            "summary": arguments.summary,
        }

        if arguments.due_date:
            params["duedate"] = arguments.due_date

        if arguments.assignee or arguments.reporter:
            all_users = self.get_paginated_results(path="users/search", result_field=None)
            user_name_to_id = {user.get("displayName"): user.get("accountId") for user in all_users}

            if arguments.assignee:
                assignee_user_id = user_name_to_id.get(arguments.assignee)
                if not assignee_user_id:
                    self.log(message="User with name `%s` is not found" % arguments.assignee, level="error")
                    return None

                params["assignee"] = {"id": assignee_user_id}

            if arguments.reporter:
                reporter_user_id = user_name_to_id.get(arguments.reporter)
                if not reporter_user_id:
                    self.log(message="User with name `%s` is not found" % arguments.reporter, level="error")
                    return None

                params["reporter"] = {"id": reporter_user_id}

        if arguments.labels:
            params["labels"] = arguments.labels.split(",")

        if arguments.parent_key:
            params["parent"] = {"key": arguments.parent_key}

        if arguments.priority:
            possible_priorities = self.get_paginated_results("priority/search")
            priority_name_to_id = {item["name"]: item["id"] for item in possible_priorities}
            priority_id = priority_name_to_id.get(arguments.priority)
            if not priority_id:
                self.log(message="Priority `%s` does not exist" % arguments.priority, level="error")
                return None

        response = self.post_json(
            "issue",
            json={"fields": params},
        )

        if "key" in response:
            return {"issue_key": response.get("key")}

        return {}

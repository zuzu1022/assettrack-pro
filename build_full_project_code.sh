#!/bin/zsh
set -e
cd '/Users/zainab/Fixed Asset Register and Depreciation Tracking System'
out='FULL_PROJECT_CODE.md'
rm -f "$out"

cat > "$out" <<'EOF'
# AssetTrack Pro - Full Project Code

## 1. Complete folder structure
```text
AssetTrack Pro Application/
│
├── app.py
├── models.py
├── seed_data.py
├── requirements.txt
├── README.md
├── static/
│   └── css/
│       └── style.css
└── templates/
    ├── base.html
    ├── login.html
    ├── change_password.html
    ├── dashboard.html
    ├── asset_list.html
    ├── asset_form.html
    ├── asset_detail.html
  ├── approvals_list.html
  ├── approval_review.html
  ├── approval_report.html
  ├── reports_hub.html
  ├── depreciation_scenario.html
    ├── depreciation_report.html
    ├── department_report.html
    ├── disposed_report.html
    ├── end_of_life_report.html
    ├── transfer_form.html
    ├── disposal_form.html
  ├── verification_form.html
  ├── verification_report.html
  ├── maintenance_form.html
  ├── maintenance_list.html
  ├── maintenance_report.html
  ├── document_list.html
  ├── document_upload_form.html
  ├── document_report.html
    ├── audit_logs.html
    ├── user_list.html
    ├── user_form.html
    ├── user_detail.html
    └── reset_password.html
```
EOF

append_section() {
  local title="$1"
  local file="$2"
  local lang="$3"
  {
    echo
    echo "## $title"
    echo "\`\`\`$lang"
    cat "$file"
    echo
    echo "\`\`\`"
  } >> "$out"
}

append_section "2. Full code for app.py" "fixed_asset_register/app.py" "python"
append_section "3. Full code for models.py" "fixed_asset_register/models.py" "python"
append_section "4. Full code for seed_data.py" "fixed_asset_register/seed_data.py" "python"
append_section "5. Full code for templates/base.html" "fixed_asset_register/templates/base.html" "html"
append_section "6. Full code for templates/login.html" "fixed_asset_register/templates/login.html" "html"
append_section "7. Full code for templates/change_password.html" "fixed_asset_register/templates/change_password.html" "html"
append_section "8. Full code for templates/dashboard.html" "fixed_asset_register/templates/dashboard.html" "html"
append_section "9. Full code for templates/asset_list.html" "fixed_asset_register/templates/asset_list.html" "html"
append_section "10. Full code for templates/asset_form.html" "fixed_asset_register/templates/asset_form.html" "html"
append_section "11. Full code for templates/asset_detail.html" "fixed_asset_register/templates/asset_detail.html" "html"
append_section "12. Full code for templates/depreciation_report.html" "fixed_asset_register/templates/depreciation_report.html" "html"
append_section "13. Full code for templates/department_report.html" "fixed_asset_register/templates/department_report.html" "html"
append_section "14. Full code for templates/disposed_report.html" "fixed_asset_register/templates/disposed_report.html" "html"
append_section "15. Full code for templates/end_of_life_report.html" "fixed_asset_register/templates/end_of_life_report.html" "html"
append_section "16. Full code for templates/transfer_form.html" "fixed_asset_register/templates/transfer_form.html" "html"
append_section "17. Full code for templates/disposal_form.html" "fixed_asset_register/templates/disposal_form.html" "html"
append_section "18. Full code for templates/audit_logs.html" "fixed_asset_register/templates/audit_logs.html" "html"
append_section "19. Full code for templates/user_list.html" "fixed_asset_register/templates/user_list.html" "html"
append_section "20. Full code for templates/user_form.html" "fixed_asset_register/templates/user_form.html" "html"
append_section "21. Full code for templates/user_detail.html" "fixed_asset_register/templates/user_detail.html" "html"
append_section "22. Full code for templates/reset_password.html" "fixed_asset_register/templates/reset_password.html" "html"
append_section "23. Full code for static/css/style.css" "fixed_asset_register/static/css/style.css" "css"
append_section "24. Full code for requirements.txt" "fixed_asset_register/requirements.txt" "txt"
append_section "25. Full code for README.md" "fixed_asset_register/README.md" "markdown"

echo "$out"

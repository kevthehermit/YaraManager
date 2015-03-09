import re

from django.db import transaction

# Import Database classes
from rule_manager.models import Rule, MetaData, RuleStrings, Condition, Category

# Create Rules from Database
blank_rule = '''
rule [[name]]
{
    meta:
[[meta]]
    strings:
[[strings]]
    condition:
        [[condition]]
}

'''
def create_single_rule(rule_id):
    #try:
        # get elements
        # get the rule
        rule_details = Rule.objects.get(id=rule_id)
        # get metadata
        meta_list = rule_details.metadata_set.all()
        meta_string = ''
        for meta in meta_list:
            meta_string += '\t\t{0} = "{1}"\n'.format(meta.meta_key, meta.meta_value)
        meta_string += '\t\tGenerated Using = "YaraManager"\n'
        
        # get strings
        string_list = rule_details.rulestrings_set.all()
        strings_string = ''
        for strings in string_list:
            if strings.string_type == 'String':
                strings_string += '\t\t{0} = "{1}"'.format(strings.string_name, strings.string_value)
                if strings.string_nocase:
                    strings_string += ' nocase'
                if strings.string_wide:
                    strings_string += ' wide'
                if strings.string_full:
                    strings_string += ' fullword'
                if strings.string_ascii:
                    strings_string += ' ascii'
                strings_string += '\n'
            if strings.string_type == 'Hex':
                strings_string += '\t\t{0} = {{{1}}}\n'.format(strings.string_name, strings.string_value)
            if strings.string_type == 'RegEx':
                strings_string += '\t\t{0} = /{1}/\n'.format(strings.string_name, strings.string_value)                
                
        # get condition
        condition = rule_details.condition_set.all()[0]
        
        # Compile Rule
        final_rule = blank_rule.replace('[[name]]', rule_details.rule_name.replace('\n', ''))
        final_rule = final_rule.replace('[[meta]]', meta_string)
        final_rule = final_rule.replace('[[strings]]', strings_string)
        final_rule = final_rule.replace('[[condition]]', condition.condition)
        
        # Return The rule
        return rule_details.rule_name.replace('\n', ''), final_rule
    #except:
        #return "Failed"

def create_multi_rule(cat_name):
    final_rule = ''
    
    # Get rules ids for cat name
    rules = Rule.objects.filter(rule_category=cat_name)
    for rule in rules:
        name, raw = create_single_rule(rule.id)
        final_rule += '{0}'.format(raw)

    return cat_name, final_rule
    
# Parse Rules from a file
def split_rules(rule_dict):
    print "Running Rules"
    raw_rules = rule_dict['rule_data']
    rule_list = re.findall('rule.*?condition:.*?}', raw_rules, re.DOTALL)
    for rule in rule_list:
        process_rule(rule, rule_dict)
               
def process_rule(single_rule, rule_dict):
    # Break a rule down in to sections
    new_rule = Rule()

    new_rule.rule_name = single_rule.split('{')[0].replace('rule ', '')
    new_rule.rule_category = rule_dict['rule_category']
    new_rule.rule_source = rule_dict['rule_source']
    new_rule.rule_version = 1
    new_rule.save()
    rule_id = new_rule.id
    
    # MetaData
    meta_list = re.findall('meta:(.*)strings:', single_rule, re.DOTALL)
    if len(meta_list) > 0:
        with transaction.commit_on_success():
            for line in meta_list[0].split('\n'):
                if '=' in line:
                    meta_lines = line.split('=')
                    key = meta_lines[0]
                    try:
                        value = re.findall('"(.*)"', line)[0]
                    except:
                        value = meta_lines[1]
                    rule_meta = MetaData(rule=new_rule, meta_key=key.strip(), meta_value=value.strip())
                    rule_meta.save()
                
    # Strings
    string_list = re.findall('strings:(.*)condition:', single_rule, re.DOTALL)
    if len(string_list) > 0:
        with transaction.commit_on_success():
            for line in string_list[0].split('\n'):
                if '=' in line:
                    string_type = False
                    # get the string ID
                    key = line.split('=')[0].strip()
                    
                    string_data = line.split('=')[1]
                    
                    string_nocase = string_wide = string_full = string_ascii = False
                    
                    if string_data.strip().startswith('"'):
                        standard_string = re.findall('"(.*)"', line)
                        if len(standard_string) != 0:
                            string_type = 'String'
                            string_value = standard_string[0]
                            if 'nocase' in line.split('"')[-1]:
                                string_nocase = True
                            if 'wide' in line.split('"')[-1]:
                                string_wide = True
                            if 'fullword' in line.split('"')[-1]:
                                string_full = True               
                            if 'ascii' in line.split('"')[-1]:
                                string_ascii = True

                    # Check for a hex string
                    if not string_type and string_data.strip().startswith('{'):
                        hex_string = re.findall('{(.*)}', line)
                        if len(hex_string) != 0:
                            string_type = 'Hex'
                            string_value = hex_string[0]
                                
                    # Check for a regex 
                    # This has an annoying habbit of matching comments
                    if not string_type and string_data.strip().startswith('/'):
                        reg_string = re.findall('/(.*)/', line)  
                        if len(reg_string) != 0:
                            if reg_string[0] not in ['', '/']:
                                string_type = 'RegEx'
                                string_value = reg_string[0]
                                
                    if string_type:
                        rule_strings = RuleStrings(rule=new_rule, 
                                    string_type = string_type, 
                                    string_name = key,
                                    string_value = string_value,
                                    string_nocase = string_nocase,
                                    string_wide = string_wide,
                                    string_full = string_full,
                                    string_ascii = string_ascii
                                    )
                        rule_strings.save()
            
            
    # Condition
    condition = re.findall('condition:(.*)}', single_rule, re.DOTALL)
    condition = condition[0].strip()
    cond_string = Condition(rule=new_rule, condition=condition)
    cond_string.save()
    
    # Store the category
    
    cat_list = []
    for name in Category.objects.all():
        cat_list.append(name.cat_name)
    if rule_dict['rule_category'] not in cat_list:
        cat = Category(cat_name=rule_dict['rule_category'])
        cat.save()
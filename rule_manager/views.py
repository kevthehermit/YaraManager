# Django Imports
from django.db import transaction
from django.shortcuts import render, redirect
from django.http import HttpResponse, Http404

from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.contrib.auth import authenticate, login, logout

# Import Database Classes
from rule_manager.models import Rule, MetaData, RuleStrings, Condition, Category

# Import Rule Parser
import ruleparser


def get_categories():
    cat_list = []
    for name in Category.objects.all():
        cat_list.append(name.cat_name)
    return cat_list


# Create your views here.

# Login Page
def login_page(request):
    try:
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                    login(request, user)
                    return redirect('/')
                else:
                    error_line = "This account has been disabled"
                    return render(request, 'error.html', {'error': error_line})
            else:
                return redirect('/')
    except:
        error_line = "Unable to login to the Web Panel"
        return redirect('/')


# Logout Page
def logout_page(request):
    logout(request)
    return redirect('/')


# Main Page
def index_view(request):
    # Get Categories for export selection
    cat_list = get_categories()
    # get list of all rules
    page = request.GET.get('page')
    if not page:
        page = 1
    page_count = request.GET.get('count')
    if not page_count:
        page_count = 10
    rule_list = Rule.objects.all()
    rule_count = rule_list.count
    first_rule =  int(page) * int(page_count) - int(page_count) + 1
    last_rule = int(page) * int(page_count)

    paginator = Paginator(rule_list, page_count)
    try:
        rules = paginator.page(page)
    except PageNotAnInteger:
        rules = paginator.page(1)
    except EmptyPage:
        rules = paginator.page(paginator.num_pages)
    return render(request, 'index.html', {'cat_list':cat_list, 'rule_list': rules, 'rule_count':rule_count, 'rules':[first_rule, last_rule]})


# Search
def search(request):
    try:
        search_type = request.POST['search_type']
        search_word = request.POST['search_word']
    except:
        return render(request, 'search.html')
    if search_type == 'name':
        results = Rule.objects.filter(rule_name__contains=search_word)
    elif search_type == 'string':
        search_rows = RuleStrings.objects.filter(string_value__contains=search_word)
        results = []
        for row in search_rows:
            results.append(row.rule)
    elif search_type == 'meta':
        search_rows = MetaData.objects.filter(meta_value__contains=search_word)
        results = []
        for row in search_rows:
            results.append(row.rule)
    else:
        error_line = "Not a valid Search"
        return render(request, 'error.html', {'error': error_line})

    return render(request, 'search.html', {'results':results, 'search':{'term':search_word, 'count':len(results)}})


# Export
# this should return a valid yara rule as a .yar
def export_rule(request, rule_id):
    rule_name, rule_object = ruleparser.create_single_rule(rule_id)
    response = HttpResponse(rule_object, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="{0}.yar"'.format(rule_name)
    return response


def export_cat(request, cat_name):
    rule_name, rule_object = ruleparser.create_multi_rule(cat_name)
    response = HttpResponse(rule_object, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="{0}.yar"'.format(rule_name)
    return response


# Rules
def rule_view(request, rule_id):
    try:
        # get the rule
        rule_details = Rule.objects.get(id=rule_id)
        # get metadata
        meta_list = rule_details.metadata_set.all()
        # get strings
        string_list = rule_details.rulestrings_set.all()
        # get condition
        condition = rule_details.condition_set.all()[0]

        return render(request, 'rule.html', {'rule_details': rule_details, 'meta_list':meta_list, 'string_list': string_list, 'condition': condition, 'string_types':['String', 'Hex', 'RegEx']})
    except Exception as e:
        return render(request, 'error.html', {'error': e})


# Update Rules with Post Data
def post_data(request, add_type):
    """
    Add Type is passed via the URI
    Valid Types and actions are:
        rule - new, update

    """
    # If not authenticated
    if not request.user.is_authenticated():
        error_line = "You need to be logged in to perform that action"
        return render(request, 'error.html', {'error': error_line})

    # Get all the POST Vars
    action = request.POST['action']

    if add_type == 'rule':
        rule_id = request.POST['rule_id']
        if action == 'delete':
            Rule.objects.filter(id=rule_id).delete()
            return redirect('/')

        if action == 'new':
            # need to get the rule details in to post before i look at this. 
            pass
        elif action == 'update':
            rule = Rule.objects.get(pk=rule_id)
            rule.rule_version += 1
            rule_condition = Condition.objects.get(rule=rule)
            rule.save()
        else:
            error_line = "Not a valid Action Type"
            return render(request, 'error.html', {'error': error_line})

        #meta data
        meta_ids = request.POST.getlist('meta_id')
        meta_values = request.POST.getlist('metaValues')
        meta_keys = request.POST.getlist('metaKeys')

        meta_save = []
        for i in range(len(meta_values)):
            if meta_ids[i] == 'new':
                meta_data = MetaData()
                meta_data.rule = rule
            else:
                meta_data = MetaData.objects.get(pk=meta_ids[i])
            meta_data.meta_key = meta_keys[i]
            meta_data.meta_value = meta_values[i]
            meta_data.save()
            meta_save.append(meta_data.id)

        # Delete Rows
        meta_db = rule.metadata_set.all()
        for obj in meta_db:
            if obj.id not in meta_save:
                print(f"dropping Meta with ID{obj.id}")
                MetaData.objects.filter(id=obj.id).delete()

        # Strings
        string_ids = request.POST.getlist('string_id')
        string_names = request.POST.getlist('stringName')
        string_values = request.POST.getlist('stringValues')
        string_nocases = request.POST.getlist('caseValues')
        string_wides = request.POST.getlist('wideValues')
        string_fulls = request.POST.getlist('fullValues')
        string_asciis = request.POST.getlist('asciiValues')

        # Collect the string vars
        string_save = []
        for i in range(len(string_names)):
            if string_ids[i] == 'new':
                rule_strings = RuleStrings()
                rule_strings.rule = rule
            else:
                rule_strings = RuleStrings.objects.get(pk=string_ids[i])

            rule_strings.string_name = string_names[i]
            rule_strings.string_value = string_values[i]
            rule_strings.string_nocase = True if string_nocases[i] == '1' else False
            rule_strings.string_wide = True if string_wides[i] == '1' else False
            rule_strings.string_full = True if string_fulls[i] == '1' else False
            rule_strings.string_ascii = True if string_asciis[i] == '1' else False
            rule_strings.save()
            string_save.append(rule_strings.id)

        # Delete Rows
        string_db = rule.rulestrings_set.all()
        for obj in string_db:
            if obj.id not in string_save:
                print(f"dropping String with ID{obj.id}")
                RuleStrings.objects.filter(id=obj.id).delete()
        return redirect('/rule/{0}'.format(rule_id))

    # Add Rules
    if add_type == 'addfile':
        rule_file = request.FILES
        rule_source = request.POST['Source']
        rule_category = request.POST['Category']
        if rule_file and action == 'new':
            rule_file = rule_file['rule_file']
            rule_data = rule_file.read()
            ruleparser.split_rules({'rule_data':rule_data, 'rule_source':rule_source, 'rule_category':rule_category})
    return redirect('/')

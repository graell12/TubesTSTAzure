#Access Calvin API
def get_bearer_token():
    response = requests.post('https://calvinfinancialconsult.azurewebsites.net/login',auth=HTTPBasicAuth('rayclementj', 'Test123'))
    jsonresponse = response.json()
    bearertoken = str(jsonresponse['access_token'])
    return bearertoken

def get_structure(url, id):
    link = url
    headers = {"Authorization": f'Bearer {get_bearer_token()}'}
    response = requests.get(link, headers=headers, json=id)
    jsonresponse = response.json()
    return jsonresponse


#Get Buying Power
@app.route("/buying_power", methods=["GET"])
@jwt_required()
def get_buying_power():
    try:
        # return buying_power()
        data=request.get_json()
        id = data['id_user']
        model = data['model']
        tenor = data['tenor']
        percent = data['percent']
        
        url = 'https://calvinfinancialconsult.azurewebsites.net/additional_spending'
        request_body = {
            'ID' : id
            }
        jsonresponse = get_structure(url, request_body)
        additionalspending = jsonresponse['total_pengeluaran_tambahan']
        harga_per_seribu = get_car_price_by_model(model)
        harga = harga_per_seribu[0] * 1000
        simulasi_kredit = get_kredit_per_bulan(model, tenor, int(percent))

        message = ''
        if additionalspending > simulasi_kredit:
            message={'message': 'You can buy this car with the given tenor :D', 'harga_mobil': harga, 'kredit_per_bulan': simulasi_kredit}
        else:
            new_tenor = 1
            while additionalspending < simulasi_kredit:
                new_tenor += 1
                simulasi_kredit = get_kredit_per_bulan(model, new_tenor, int(percent))
            message={'message': 'Sorry, you cannot buy this car with the given tenor :( try to increase the tenor', 'recommended_tenor_years': new_tenor}
        return jsonify(message)
    except Exception as e:
        return(e)
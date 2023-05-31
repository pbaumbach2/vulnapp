# CrowdStrike's VulnApp
[![Docker Repository on Quay](https://quay.io/repository/crowdstrike/vulnapp/status "Docker Repository on Quay")](https://quay.io/repository/crowdstrike/vulnapp)

## Usage

```
kubectl apply -f  https://raw.githubusercontent.com/crowdstrike/vulnapp/main/vulnerable.example.yaml
```

Get web address:
```
watch -n 1 echo 'http://$(kubectl get service vulnerable-example-com  -o yaml -o=jsonpath="{.status.loadBalancer.ingress[0].ip}")/'
```

If the `ip` field is not present try:
```

watch -n 1 echo 'http://$(kubectl get service vulnerable-example-com  -o yaml -o=jsonpath="{.status.loadBalancer.ingress[0].hostname}")/'
```

Delete the app:
```
kubectl delete -f  https://raw.githubusercontent.com/crowdstrike/vulnapp/main/vulnerable.example.yaml
```

curl -s "https://rapiddns.io/subdomain/$1?full=1" | grep -oP '_blank">\K[^<]*' | grep -v http | sort -u

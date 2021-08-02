from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.decorators import api_view
from rest_framework.response import Response
from .products import products
from .models import Product 
from .serializers import ProductSerializer 
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated


@api_view(['GET'])
def getRoutes(request):
    
    #return JsonResponse('hello',safe=False)
    routes=[
        '/prapi/products/',
        '/prapi/products/create/',
        '/prapi/products/upload/',
        '/api/products/<id>/reviews/', 
        
        '/api/products/top/',
        '/api/products/<id>/',
        
        
        '/api/products/delete/<id>/',
        '/api/products/<update>/<id>/',
        
    ]
    return Response(routes)


@api_view(['GET'])
@permission_classes((AllowAny, ))
def getProducts(request):
    products=Product.objects.all()
    serializer=ProductSerializer(products,many=True)
    print(serializer.data)
    return Response(serializer.data)




@api_view(['GET'])
def getProduct(request,pk):
    product=Product.objects.get(_id=pk)
    serializer=ProductSerializer(product,many=False) 
    return Response(serializer.data)





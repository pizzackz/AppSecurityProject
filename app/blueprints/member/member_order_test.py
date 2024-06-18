
#Testing to see if orders are being created and stored in the database

from app import create_app, db
from app.models import Order, OrderItem

app = create_app()

with app.app_context():
    orders = Order.query.all()

    # Clear the database before running the test
    # try:
    #     # Delete all OrderItem records
    #     db.session.query(OrderItem).delete()
    #     db.session.commit()
    #
    #     # Delete all Order records
    #     db.session.query(Order).delete()
    #     db.session.commit()
    #
    #     print("All orders and order items have been cleared.")
    #
    # except Exception as e:
    #     db.session.rollback()
    #     print(f"An error occurred while clearing the orders: {e}")

    # Testing to see if orders are being created and stored in the database
    for order in orders:
        print(order)
        for item in order.items:
            print(f" Item -  {item.menu_item.name} ({item.menu_item.id}) \n Quantity - {item.quantity} \n "
                  f"\nCustomer Information \n Name - {order.customer_name} \n Address - {order.address} \n Postal Code - {order.postal_code} \n Phone Number - {order.phone_number} \n "
                  f"\nOrder Information \n Delivery Date - {order.delivery_date} \n Delivery Time - {order.delivery_time} \n Order Created At - {order.created_at} \n")